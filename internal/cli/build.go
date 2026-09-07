package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/base"
	"niflhel/internal/daemon"
	"niflhel/internal/filecopy"
	"niflhel/internal/fsutil"
	"niflhel/internal/oci"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func BuildArgs(endpoint, contextDir, dockerfile, output, target string, args []string) []string {
	out := []string{"--addr", endpoint, "build", "--frontend", "dockerfile.v0", "--local", "context=" + contextDir, "--local", "dockerfile=" + filepath.Dir(dockerfile), "--opt", "filename=" + filepath.Base(dockerfile), "--opt", "platform=linux/amd64", "--output", "type=oci,dest=" + output}
	if target != "" {
		out = append(out, "--opt", "target="+target)
	}
	for _, arg := range args {
		out = append(out, "--opt", "build-arg:"+arg)
	}
	return out
}
func (a *App) buildCommand(isBase bool) *cobra.Command {
	var tag, file, target, recipe, keyPath, keyID, kernel, fcVersion string
	var buildArgs []string
	c := &cobra.Command{Use: "build [OPTIONS] CONTEXT", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		if tag == "" {
			return fmt.Errorf("--tag required")
		}
		endpoint := os.Getenv("BUILDKIT_HOST")
		if endpoint == "" {
			return fmt.Errorf("set BUILDKIT_HOST to an explicitly configured BuildKit service")
		}
		contextDir, e := filepath.Abs(args[0])
		if e != nil {
			return e
		}
		df := file
		if !filepath.IsAbs(df) {
			df = filepath.Join(contextDir, df)
		}
		if _, e = os.Stat(df); e != nil {
			return e
		}
		if isBase && (keyPath == "" || keyID == "" || fcVersion == "") {
			return fmt.Errorf("base build requires --signing-key, --key-id, and --firecracker-version")
		}
		packager := os.Getenv("NIFLHEL_BASE_PACKAGER")
		if isBase && packager == "" {
			return fmt.Errorf("set NIFLHEL_BASE_PACKAGER to an isolated packaging-worker wrapper")
		}
		tmp, e := os.MkdirTemp("", "niflhel-build-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(tmp)
		output := filepath.Join(tmp, "image.tar")
		bargs := BuildArgs(endpoint, contextDir, df, output, target, buildArgs)
		if strings.HasPrefix(endpoint, "tcp://") {
			tlsArgs := []string{}
			for _, pair := range [][2]string{{"BUILDKIT_TLS_CA_CERT", "--tlscacert"}, {"BUILDKIT_TLS_CERT", "--tlscert"}, {"BUILDKIT_TLS_KEY", "--tlskey"}} {
				value := os.Getenv(pair[0])
				if value == "" {
					return fmt.Errorf("%s required for authenticated remote BuildKit", pair[0])
				}
				tlsArgs = append(tlsArgs, pair[1], value)
			}
			bargs = append(append(bargs[:2:2], tlsArgs...), bargs[2:]...)
		}
		cmd := exec.CommandContext(c.Context(), "buildctl", bargs...)
		cmd.Stdout = a.Err
		cmd.Stderr = a.Err
		if e = cmd.Run(); e != nil {
			return e
		}
		if !isBase {
			f, e := os.Open(output)
			if e != nil {
				return e
			}
			defer f.Close()
			return a.upload(c.Context(), "image-load", tag, f)
		}
		var cfg struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
			Spec       struct {
				Platform string `yaml:"platform"`
				Kernel   struct {
					Ref string `yaml:"ref"`
				} `yaml:"kernel"`
			} `yaml:"spec"`
		}
		rp := recipe
		if !filepath.IsAbs(rp) {
			rp = filepath.Join(contextDir, rp)
		}
		data, e := os.ReadFile(rp)
		if e != nil {
			return e
		}
		if e = yaml.Unmarshal(data, &cfg); e != nil {
			return e
		}
		if cfg.APIVersion != "niflhel.dev/v1alpha1" || cfg.Kind != "BaseRecipe" || cfg.Spec.Platform != "linux/amd64" {
			return fmt.Errorf("unsupported base recipe")
		}
		bundle := filepath.Join(tmp, "bundle")
		os.Mkdir(bundle, 0700)
		pargs := []string{"--image", output, "--output", bundle}
		if kernel != "" {
			pargs = append(pargs, "--kernel", kernel)
		} else {
			if !strings.Contains(cfg.Spec.Kernel.Ref, "@sha256:") {
				return fmt.Errorf("kernel image must be digest-pinned")
			}
			pargs = append(pargs, "--kernel-image", cfg.Spec.Kernel.Ref)
		}
		cmd = exec.CommandContext(c.Context(), packager, pargs...)
		cmd.Stdout = a.Err
		cmd.Stderr = a.Err
		if e = cmd.Run(); e != nil {
			return e
		}
		descriptor := func(path, media string) (oci.Descriptor, error) {
			h, n, e := fsutil.DigestFile(path)
			return oci.Descriptor{Digest: h, Size: n, MediaType: media}, e
		}
		kd, e := descriptor(filepath.Join(bundle, "kernel"), "application/vnd.niflhel.kernel.v1")
		if e != nil {
			return e
		}
		rd, e := descriptor(filepath.Join(bundle, "rootfs.ext4"), "application/vnd.niflhel.rootfs.ext4.v1")
		if e != nil {
			return e
		}
		keyBytes, e := os.ReadFile(keyPath)
		if e != nil {
			return e
		}
		key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyBytes)))
		if e != nil {
			return e
		}
		signed, e := base.Sign(base.Config{SchemaVersion: 1, OS: "linux", Architecture: "amd64", AgentProtocol: 1, InitPath: "/sbin/niflhel-init", Runtime: "runc", GuestReserveMiB: 128, FirecrackerVersions: []string{fcVersion}, Kernel: kd, RootFS: rd}, keyID, ed25519.PrivateKey(key))
		if e != nil {
			return e
		}
		if e = fsutil.JSON(filepath.Join(bundle, "signed.json"), signed); e != nil {
			return e
		}
		r, w := io.Pipe()
		go func() { e := filecopy.Archive(bundle, ".", w); w.CloseWithError(e) }()
		defer r.Close()
		if e = a.upload(c.Context(), "base-load", tag, r); e != nil {
			return e
		}
		auth, _ := json.Marshal(daemon.Auth{App: AuthFor("busybox:1.37")})
		var report any
		if e = a.call(c.Context(), api.Request{Action: "base-validate", Ref: tag, Data: auth}, &report); e != nil {
			return fmt.Errorf("base staged, but boot validation failed: %w", e)
		}
		return a.print(report)
	}}
	c.Flags().StringVarP(&tag, "tag", "t", "", "output image/base reference")
	c.Flags().StringVarP(&file, "file", "f", "Dockerfile", "Dockerfile")
	c.Flags().StringVar(&target, "target", "", "build target")
	c.Flags().StringArrayVar(&buildArgs, "build-arg", nil, "KEY=VALUE build argument")
	if isBase {
		c.Flags().StringVar(&recipe, "config", "base.yaml", "base recipe")
		c.Flags().StringVar(&keyPath, "signing-key", "", "base64 Ed25519 private-key file")
		c.Flags().StringVar(&keyID, "key-id", "", "trusted publisher key ID")
		c.Flags().StringVar(&kernel, "kernel", "", "local kernel supplied to packaging worker")
		c.Flags().StringVar(&fcVersion, "firecracker-version", "", "qualified Firecracker version")
	}
	return c
}
