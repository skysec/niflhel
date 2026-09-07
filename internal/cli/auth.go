package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"io"
	"os"
	"os/exec"
	"strings"
)

func readEnv(path string) ([]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	out := []string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSuffix(s.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k, _, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("env-file requires KEY=VALUE")
		}
		out = append(out, line)
	}
	return out, s.Err()
}
func AuthFor(ref string) *authn.AuthConfig {
	if ref == "" {
		return nil
	}
	r, e := name.ParseReference(ref)
	if e != nil {
		return nil
	}
	helper := os.Getenv("NIFLHEL_CREDENTIAL_HELPER")
	if helper != "" {
		cmd := exec.Command("docker-credential-"+helper, "get")
		cmd.Stdin = strings.NewReader(r.Context().RegistryStr() + "\n")
		b, e := cmd.Output()
		if e != nil {
			return nil
		}
		var v struct {
			Username string
			Secret   string
		}
		if json.Unmarshal(b, &v) != nil {
			return nil
		}
		return &authn.AuthConfig{Username: v.Username, Password: v.Secret}
	}
	auth, e := authn.DefaultKeychain.Resolve(r.Context())
	if e != nil {
		return nil
	}
	v, e := auth.Authorization()
	if e != nil {
		return nil
	}
	return v
}
func (a *App) login(logout bool) *cobra.Command {
	user := ""
	stdin := false
	cmdName := "login"
	if logout {
		cmdName = "logout"
	}
	c := &cobra.Command{Use: cmdName + " REGISTRY", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		helper := os.Getenv("NIFLHEL_CREDENTIAL_HELPER")
		if helper == "" {
			return fmt.Errorf("set NIFLHEL_CREDENTIAL_HELPER to an installed Docker credential helper (for example pass); passwords are not stored in plaintext")
		}
		action := "erase"
		data := []byte(args[0] + "\n")
		if !logout {
			if !stdin || user == "" {
				return fmt.Errorf("--username and --password-stdin are required")
			}
			b, e := io.ReadAll(io.LimitReader(a.In, 65537))
			if e != nil {
				return e
			}
			if len(b) > 65536 {
				return fmt.Errorf("password too long")
			}
			data, _ = json.Marshal(map[string]string{"ServerURL": args[0], "Username": user, "Secret": strings.TrimSuffix(string(b), "\n")})
			action = "store"
		}
		cmd := exec.CommandContext(c.Context(), "docker-credential-"+helper, action)
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stdout = a.Out
		cmd.Stderr = a.Err
		return cmd.Run()
	}}
	if !logout {
		c.Flags().StringVarP(&user, "username", "u", "", "registry user")
		c.Flags().BoolVar(&stdin, "password-stdin", false, "read password from stdin")
	}
	return c
}
