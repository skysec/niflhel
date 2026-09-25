package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"niflhel/internal/api"
	"niflhel/internal/base"
	"niflhel/internal/filecopy"
	"niflhel/internal/fsutil"
	"niflhel/internal/journal"
	"niflhel/internal/oci"
	"niflhel/internal/wire"
	"os"
	"path/filepath"
	"time"
)

func (d *Daemon) Call(ctx context.Context, q api.Request) (any, error) {
	var auth Auth
	if len(q.Data) > 0 && (q.Action == "create" || q.Action == "pull" || q.Action == "base-pull" || q.Action == "base-push" || q.Action == "base-validate") {
		if e := json.Unmarshal(q.Data, &auth); e != nil {
			return nil, e
		}
	}
	switch q.Action {
	case "version":
		return map[string]any{"Version": api.Version, "Protocol": api.Protocol}, nil
	case "info":
		return map[string]any{"Version": api.Version, "Protocol": api.Protocol, "DefaultBase": d.Config.DefaultBase, "Runtime": "runc", "NetworkModes": []string{"bridge", "none"}, "Root": d.Config.Root, "Phase": 1}, nil
	case "create":
		if q.Spec == nil {
			return nil, fmt.Errorf("spec required")
		}
		return d.Create(ctx, *q.Spec, auth)
	case "start":
		return d.Start(ctx, q.ID)
	case "inspect":
		return d.Store.Get(q.ID)
	case "ps":
		return d.Store.List()
	case "stop":
		return nil, d.Stop(ctx, q.ID, q.Timeout)
	case "restart":
		if e := d.Stop(ctx, q.ID, q.Timeout); e != nil {
			return nil, e
		}
		return d.Start(ctx, q.ID)
	case "rm":
		return nil, d.Remove(ctx, q.ID, q.Force)
	case "wait":
		return d.Wait(ctx, q.ID)
	case "kill":
		s, e := d.Store.Get(q.ID)
		if e != nil {
			return nil, e
		}
		if s.State != "running" && s.State != "stopping" {
			return nil, fmt.Errorf("container not running")
		}
		c, e := d.VM.Client(s)
		if e != nil {
			return nil, e
		}
		return nil, c.Call(ctx, api.Request{Action: "signal", Signal: q.Signal}, nil)
	case "logs":
		s, e := d.Store.Get(q.ID)
		logPath := ""
		if e == nil {
			logPath = filepath.Join(d.dir(s.ID), "application.log")
		} else {
			saved, e := d.findResult(q.ID)
			if e != nil {
				return nil, e
			}
			logPath = filepath.Join(d.Config.Root, "results", saved.ID+".log")
		}
		var cursor uint64
		if len(q.Data) > 0 {
			if e = json.Unmarshal(q.Data, &cursor); e != nil {
				return nil, e
			}
		}
		return journal.Open(logPath).Read(cursor), nil
	case "pull":
		return d.Images.Pull(ctx, q.Ref, "always", auth.App)
	case "images":
		return d.Images.List()
	case "image-inspect":
		return d.Images.Get(q.Ref)
	case "image-rm":
		lock := d.lock("allocations")
		defer lock()
		img, e := d.Images.Get(q.Ref)
		if e != nil {
			return nil, e
		}
		all, e := d.Store.List()
		if e != nil {
			return nil, e
		}
		for _, s := range all {
			if s.ImageDigest == img.Digest {
				return nil, fmt.Errorf("image referenced by %s", s.Name)
			}
		}
		return nil, d.Images.Remove(q.Ref)
	case "base-validate":
		return d.ValidateBase(ctx, q.Ref, auth)
	case "base-pull":
		return d.Bases.Pull(ctx, q.Ref, "always", auth.Base)
	case "base-push":
		return nil, d.Bases.Push(ctx, q.Ref, auth.Base)
	case "base-ls":
		return d.Bases.List()
	case "base-inspect":
		return d.Bases.Get(q.Ref)
	case "base-rm":
		lock := d.lock("allocations")
		defer lock()
		b, e := d.Bases.Get(q.Ref)
		if e != nil {
			return nil, e
		}
		all, e := d.Store.List()
		if e != nil {
			return nil, e
		}
		for _, s := range all {
			if s.BaseDigest == b.Digest {
				return nil, fmt.Errorf("base referenced by %s", s.Name)
			}
		}
		return nil, d.Bases.Remove(q.Ref)
	case "volume-ls":
		return d.Store.Volumes()
	case "volume-inspect":
		return d.Store.Volume(q.ID)
	case "volume-create":
		lock := d.lock("allocations")
		defer lock()
		if q.Volume == nil || !api.ValidName(q.Volume.Name) {
			return nil, fmt.Errorf("valid volume name required")
		}
		v := *q.Volume
		v.Created = time.Now().UTC()
		p, e := d.Storage.VolumePath(v.Name)
		if e != nil {
			return nil, e
		}
		if e = d.Storage.Disk(ctx, p, v.Size, ""); e != nil {
			return nil, e
		}
		if e = d.Store.PutVolume(v); e != nil {
			os.Remove(p)
			return nil, e
		}
		return v, nil
	case "volume-rm":
		lock := d.lock("allocations")
		defer lock()
		v, e := d.Store.Volume(q.ID)
		if e != nil {
			return nil, e
		}
		all, e := d.Store.List()
		if e != nil {
			return nil, e
		}
		for _, s := range all {
			for _, m := range s.Spec.Mounts {
				if m.Name == v.Name {
					return nil, fmt.Errorf("volume referenced by %s", s.Name)
				}
			}
		}
		p, e := d.Storage.VolumePath(v.Name)
		if e != nil {
			return nil, e
		}
		if e = os.Remove(p); e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		return nil, d.Store.DeleteVolume(v.Name)
	default:
		return nil, fmt.Errorf("UnsupportedFeature: operation %q", q.Action)
	}
}
func (d *Daemon) Session(ctx context.Context, q api.Request, s *wire.Stream) error {
	if q.Action == "image-load" || q.Action == "base-load" {
		return d.load(ctx, q, s)
	}
	v, e := d.Store.Get(q.ID)
	if q.Action == "attach" && (e != nil || v.State == "exited" || v.State == "failed") {
		return d.retainedAttach(ctx, q.ID, s)
	}
	if e != nil {
		return e
	}
	if v.State != "running" && v.State != "stopping" {
		return fmt.Errorf("container not running")
	}
	if q.Action != "exec" && q.Action != "attach" && q.Action != "copy-in" && q.Action != "copy-out" {
		return fmt.Errorf("unsupported session")
	}
	c, e := d.VM.Client(v)
	if e != nil {
		return e
	}
	up, e := c.Session(ctx, q)
	if e != nil {
		return e
	}
	defer up.Close()
	return wire.Relay(s, up)
}
func (d *Daemon) load(ctx context.Context, q api.Request, s *wire.Stream) error {
	if q.Ref == "" {
		return fmt.Errorf("image reference required")
	}
	tmp, e := os.MkdirTemp(d.Config.Root, "load-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	r, w := io.Pipe()
	defer r.Close()
	go func() {
		defer w.Close()
		for {
			var f api.Frame
			if e := s.Recv(&f); e != nil {
				w.CloseWithError(e)
				return
			}
			if f.Type == "eof" {
				return
			}
			if f.Type != "data" {
				w.CloseWithError(fmt.Errorf("invalid upload frame"))
				return
			}
			if _, e := w.Write(f.Data); e != nil {
				return
			}
		}
	}()
	if e = filecopy.Extract(tmp, ".", r); e != nil {
		return e
	}
	if q.Action == "image-load" {
		img, e := oci.LoadLayoutImage(tmp)
		if e != nil {
			return e
		}
		v, e := d.Images.Import(ctx, q.Ref, img)
		if e != nil {
			return e
		}
		return s.Send(api.Frame{Type: "exit", Message: v.Digest})
	}
	raw, e := fsutil.ReadFileLimit(filepath.Join(tmp, "signed.json"), base.MaxSignedMetadata)
	if e != nil {
		return e
	}
	signed, e := base.ParseSigned(raw)
	if e != nil {
		return e
	}
	b, e := d.Bases.Import(q.Ref, signed, filepath.Join(tmp, "kernel"), filepath.Join(tmp, "rootfs.ext4"))
	if e != nil {
		return e
	}
	return s.Send(api.Frame{Type: "exit", Message: b.Digest})
}
