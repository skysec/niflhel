package oci

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"niflhel/internal/fsutil"
	"path/filepath"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const MaxMetadata int64 = 4 << 20

const (
	maxMetadataTokens      = 100000
	maxMetadataDepth       = 100
	maxMetadataResponses   = 32
	maxMetadataStringBytes = MaxMetadata
)

func decodeMetadata(raw []byte, out any) error {
	if int64(len(raw)) > MaxMetadata {
		return fmt.Errorf("OCI metadata size limit exceeded")
	}
	if e := fsutil.ValidateJSONComplexity(raw, maxMetadataTokens, maxMetadataDepth, maxMetadataStringBytes); e != nil {
		return fmt.Errorf("invalid OCI metadata: %w", e)
	}
	if e := json.Unmarshal(raw, out); e != nil {
		return fmt.Errorf("invalid OCI metadata: %w", e)
	}
	return nil
}

func layoutBlob(root string, d v1.Descriptor) ([]byte, error) {
	if d.Size < 0 || d.Size > MaxMetadata {
		return nil, fmt.Errorf("OCI metadata descriptor size limit exceeded")
	}
	hex, e := fsutil.HexDigest(d.Digest.String())
	if e != nil {
		return nil, e
	}
	// The layout implementation consumes the digest-addressed file. Reject an
	// inline alternate representation so admission and use cannot diverge.
	if len(d.Data) != 0 {
		return nil, fmt.Errorf("inline OCI layout metadata is unsupported")
	}
	raw, e := fsutil.ReadFileLimit(filepath.Join(root, "blobs", "sha256", hex), MaxMetadata)
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) != d.Size || fsutil.Digest(raw) != d.Digest.String() {
		return nil, fmt.Errorf("OCI metadata descriptor integrity failure")
	}
	return raw, nil
}

// LoadLayoutImage admits every parsed layout metadata object before handing
// the selected image to go-containerregistry. Application layer contents stay
// opaque and are streamed later by Store.Import.
func LoadLayoutImage(root string) (v1.Image, error) {
	layoutRaw, e := fsutil.ReadFileLimit(filepath.Join(root, "oci-layout"), MaxMetadata)
	if e != nil {
		return nil, e
	}
	if e = fsutil.ValidateJSONComplexity(layoutRaw, 64, 8, 4096); e != nil {
		return nil, fmt.Errorf("invalid OCI layout metadata: %w", e)
	}
	indexRaw, e := fsutil.ReadFileLimit(filepath.Join(root, "index.json"), MaxMetadata)
	if e != nil {
		return nil, e
	}
	var index v1.IndexManifest
	if e = decodeMetadata(indexRaw, &index); e != nil {
		return nil, e
	}
	if len(index.Manifests) != 1 {
		return nil, fmt.Errorf("build/load must contain exactly one platform image")
	}
	selected := index.Manifests[0]
	if selected.MediaType != types.OCIManifestSchema1 && selected.MediaType != types.DockerManifestSchema2 {
		return nil, fmt.Errorf("build/load must select an OCI or Docker schema-2 image")
	}
	manifestRaw, e := layoutBlob(root, selected)
	if e != nil {
		return nil, e
	}
	var manifest v1.Manifest
	if e = decodeMetadata(manifestRaw, &manifest); e != nil {
		return nil, e
	}
	configRaw, e := layoutBlob(root, manifest.Config)
	if e != nil {
		return nil, e
	}
	var config v1.ConfigFile
	if e = decodeMetadata(configRaw, &config); e != nil {
		return nil, e
	}
	lp, e := layout.FromPath(root)
	if e != nil {
		return nil, e
	}
	return lp.Image(selected.Digest)
}

// MetadataTransport bounds response bodies only while Limit is active. Pull
// callers activate it around manifest/index and config operations, never layer
// transfers, so large application artifacts keep their existing limits.
type MetadataTransport struct {
	base      http.RoundTripper
	max       int64
	total     int64
	mu        sync.Mutex
	active    int
	responses int
	used      int64
}

func NewMetadataTransport(base http.RoundTripper, max, total int64) *MetadataTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &MetadataTransport{base: base, max: max, total: total}
}

func (t *MetadataTransport) Limit() func() {
	t.mu.Lock()
	t.active++
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			t.active--
			t.mu.Unlock()
		})
	}
}

func (t *MetadataTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, e := t.base.RoundTrip(req)
	if e != nil {
		return nil, e
	}
	t.mu.Lock()
	limited := t.active > 0
	if limited {
		t.responses++
		if t.responses > maxMetadataResponses || t.max < 0 || t.total < 0 || resp.ContentLength > t.max || (resp.ContentLength >= 0 && resp.ContentLength > t.total-t.used) {
			t.mu.Unlock()
			resp.Body.Close()
			return nil, fmt.Errorf("OCI metadata response limit exceeded")
		}
	}
	t.mu.Unlock()
	if limited {
		resp.Body = &metadataBody{ReadCloser: resp.Body, owner: t, max: t.max}
	}
	return resp, nil
}

type metadataBody struct {
	io.ReadCloser
	owner *MetadataTransport
	max   int64
	read  int64
	mu    sync.Mutex
}

func (b *metadataBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.owner.mu.Lock()
	perRemaining := b.max - b.read
	totalRemaining := b.owner.total - b.owner.used
	if perRemaining < 0 || totalRemaining < 0 {
		b.owner.mu.Unlock()
		return 0, fmt.Errorf("OCI metadata response limit exceeded")
	}
	allowed := int64(len(p))
	if allowed > perRemaining+1 {
		allowed = perRemaining + 1
	}
	if allowed > totalRemaining+1 {
		allowed = totalRemaining + 1
	}
	if allowed <= 0 {
		b.owner.mu.Unlock()
		return 0, fmt.Errorf("OCI metadata response limit exceeded")
	}
	// Reserve before the potentially blocking network read so concurrent
	// responses cannot collectively exceed the aggregate budget.
	b.owner.used += allowed
	b.owner.mu.Unlock()
	n, e := b.ReadCloser.Read(p[:allowed])
	b.owner.mu.Lock()
	b.owner.used -= allowed - int64(n)
	b.read += int64(n)
	over := b.read > b.max || b.owner.used > b.owner.total
	b.owner.mu.Unlock()
	if over {
		return n, fmt.Errorf("OCI metadata response limit exceeded")
	}
	return n, e
}
