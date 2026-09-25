// niflhel-pack runs on an explicitly isolated build worker, never as a
// privileged subcommand of niflheld. It converts a Dockerfile result into ext4.
package main

import (
	"archive/tar"
	"context"
	"flag"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/filecopy"
	"niflhel/internal/guest"
	"niflhel/internal/oci"
	"niflhel/internal/storage"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const kernelImageTimeout = 10 * time.Minute

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	input := flag.String("image", "", "OCI-layout tar from BuildKit")
	output := flag.String("output", "", "output directory")
	kernel := flag.String("kernel", "", "local ELF kernel")
	kernelImage := flag.String("kernel-image", "", "digest-pinned kernel OCI image")
	flag.Parse()
	if os.Getenv("NIFLHEL_ISOLATED_BUILD_WORKER") != "1" {
		return fmt.Errorf("refusing to unpack without NIFLHEL_ISOLATED_BUILD_WORKER=1 (set NIFLHEL_ISOLATED_BUILD_WORKER only inside an isolated build worker)")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("base packaging requires root inside the isolated worker to preserve image ownership")
	}
	if *input == "" || *output == "" {
		return fmt.Errorf("--image and --output required")
	}
	tmp, e := os.MkdirTemp("", "niflhel-pack-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	ctx := context.Background()
	layoutDir := filepath.Join(tmp, "layout")
	os.Mkdir(layoutDir, 0700)
	f, e := os.Open(*input)
	if e != nil {
		return e
	}
	e = filecopy.Extract(layoutDir, ".", f)
	f.Close()
	if e != nil {
		return e
	}
	image, e := oci.LoadLayoutImage(layoutDir)
	if e != nil {
		return e
	}
	cache := oci.New(filepath.Join(tmp, "cache"))
	img, e := cache.Import(ctx, "base-build", image)
	if e != nil {
		return e
	}
	carrier := filepath.Join(tmp, "carrier")
	if e = cache.Carrier(carrier, img); e != nil {
		return e
	}
	root := filepath.Join(tmp, "rootfs")
	os.Mkdir(root, 0700)
	if e = guest.Unpack(ctx, carrier, root, 2*api.GiB); e != nil {
		return e
	}
	for _, p := range []string{"sbin/niflhel-init", "usr/sbin/niflhel-agent", "usr/bin/runc", "usr/sbin/ip", "usr/sbin/iptables"} {
		// Distributions vary the path of network helpers; validate those on boot.
		if strings.HasPrefix(p, "usr/sbin/") && p != "usr/sbin/niflhel-agent" {
			continue
		}
		st, e := os.Stat(filepath.Join(root, p))
		if e != nil || !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
			return fmt.Errorf("required guest executable missing: %s", p)
		}
	}
	if e = os.MkdirAll(*output, 0700); e != nil {
		return e
	}
	outKernel := filepath.Join(*output, "kernel")
	if *kernel != "" {
		src, e := os.Open(*kernel)
		if e != nil {
			return e
		}
		defer src.Close()
		dst, e := os.OpenFile(outKernel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = io.Copy(dst, io.LimitReader(src, 128*api.MiB))
		dst.Close()
		if e != nil {
			return e
		}
	} else if e = writeKernelFromImage(ctx, *kernelImage, outKernel); e != nil {
		return e
	}
	size := int64(0)
	filepath.Walk(root, func(_ string, i os.FileInfo, e error) error {
		if e == nil && i.Mode().IsRegular() {
			size += i.Size()
		}
		return e
	})
	return (storage.Manager{}).Disk(ctx, filepath.Join(*output, "rootfs.ext4"), storage.CarrierSize(size), root)
}

func writeKernelFromImage(ctx context.Context, imageRef, outKernel string) error {
	if !strings.Contains(imageRef, "@sha256:") {
		return fmt.Errorf("kernel image must be digest-pinned")
	}
	ref, e := name.ParseReference(imageRef)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, kernelImageTimeout)
	defer cancel()
	metadata := oci.NewMetadataTransport(remote.DefaultTransport, oci.MaxMetadata, 8*oci.MaxMetadata)
	stopMetadata := metadata.Limit()
	img, e := remote.Image(ref, remote.WithContext(ctx), remote.WithTransport(metadata))
	stopMetadata()
	if e != nil {
		return e
	}
	r := mutate.Extract(img)
	defer r.Close()
	tr := tar.NewReader(io.LimitReader(r, 512*api.MiB))
	for {
		h, e := tr.Next()
		if e == io.EOF {
			return fmt.Errorf("kernel image lacks regular /boot/vmlinux")
		}
		if e != nil {
			return e
		}
		if strings.TrimPrefix(h.Name, "./") != "boot/vmlinux" {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size > 128*api.MiB {
			return fmt.Errorf("kernel must be regular /boot/vmlinux under 128 MiB")
		}
		dst, e := os.OpenFile(outKernel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = io.CopyN(dst, tr, h.Size)
		dst.Close()
		return e
	}
}
