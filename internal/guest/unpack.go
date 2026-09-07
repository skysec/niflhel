package guest

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/klauspost/compress/zstd"
	"io"
	"niflhel/internal/fsutil"
	"niflhel/internal/oci"
	"os"
	"path/filepath"
	"strings"
)

type closer struct {
	io.Reader
	close func() error
}

func (c closer) Close() error { return c.close() }
func layerReader(p, media string) (io.ReadCloser, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	if strings.Contains(media, "gzip") {
		r, e := gzip.NewReader(f)
		if e != nil {
			f.Close()
			return nil, e
		}
		return closer{r, func() error { r.Close(); return f.Close() }}, nil
	}
	if strings.Contains(media, "zstd") {
		r, e := zstd.NewReader(f, zstd.WithDecoderMaxMemory(128<<20))
		if e != nil {
			f.Close()
			return nil, e
		}
		return closer{r, func() error { r.Close(); return f.Close() }}, nil
	}
	if media == "application/vnd.oci.image.layer.v1.tar" || media == "application/vnd.docker.image.rootfs.diff.tar" {
		return f, nil
	}
	f.Close()
	return nil, fmt.Errorf("unsupported layer media type %q", media)
}
func Unpack(ctx context.Context, carrier, dest string, maxBytes int64) error {
	var img oci.Image
	if e := fsutil.ReadJSON(filepath.Join(carrier, "image.json"), &img); e != nil {
		return e
	}
	if len(img.Layers) != len(img.DiffIDs) || len(img.Layers) > 256 {
		return fmt.Errorf("invalid layer metadata")
	}
	var total int64
	entries := 0
	for i, d := range img.Layers {
		h, e := fsutil.HexDigest(d.Digest)
		if e != nil {
			return e
		}
		p := filepath.Join(carrier, "blobs", h)
		actual, n, e := fsutil.DigestFile(p)
		if e != nil || actual != d.Digest || n != d.Size {
			return fmt.Errorf("layer integrity failure")
		}
		r, e := layerReader(p, d.MediaType)
		if e != nil {
			return e
		}
		// Bound and verify expanded bytes before applying a layer. The spool stays
		// in the guest's quota-limited state disk, never on the host.
		tmp, e := os.CreateTemp(filepath.Dir(dest), ".layer-")
		if e != nil {
			r.Close()
			return e
		}
		n, e = io.Copy(tmp, io.LimitReader(r, maxBytes-total+1))
		r.Close()
		tmp.Close()
		if e != nil || n > maxBytes-total {
			os.Remove(tmp.Name())
			return fmt.Errorf("expanded image exceeds disk budget")
		}
		total += n
		diff, _, e := fsutil.DigestFile(tmp.Name())
		if e != nil || diff != img.DiffIDs[i] {
			os.Remove(tmp.Name())
			return fmt.Errorf("uncompressed layer digest mismatch")
		}
		f, e := os.Open(tmp.Name())
		if e != nil {
			return e
		}
		tr := tar.NewReader(f)
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				f.Close()
				os.Remove(tmp.Name())
				return e
			}
			entries++
			clean := filepath.Clean(h.Name)
			if entries > 200000 || filepath.IsAbs(h.Name) || clean == ".." || strings.HasPrefix(clean, "../") {
				f.Close()
				os.Remove(tmp.Name())
				return fmt.Errorf("unsafe layer path or inode limit")
			}
			if h.Typeflag == tar.TypeChar || h.Typeflag == tar.TypeBlock || h.Typeflag == tar.TypeFifo {
				f.Close()
				os.Remove(tmp.Name())
				return fmt.Errorf("special files not supported in app images")
			}
		}
		f.Seek(0, 0)
		opts := []archive.ApplyOpt{}
		if os.Geteuid() != 0 {
			opts = append(opts, archive.WithNoSameOwner())
		}
		_, e = archive.Apply(ctx, dest, f, opts...)
		f.Close()
		os.Remove(tmp.Name())
		if e != nil {
			return e
		}
	}
	return nil
}
