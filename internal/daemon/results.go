package daemon

import (
	"context"
	"fmt"
	"niflhel/internal/api"
	"niflhel/internal/fsutil"
	"niflhel/internal/journal"
	"niflhel/internal/state"
	"niflhel/internal/wire"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type result struct {
	api.Exit
	ID   string
	Name string
}

const resultRetention = 24 * time.Hour

func (d *Daemon) saveResult(v api.Sandbox, exit *api.Exit) error {
	d.resultMu.Lock()
	defer d.resultMu.Unlock()
	dir := filepath.Join(d.Config.Root, "results")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for _, suffix := range []string{"", ".1"} {
		source := filepath.Join(d.dir(v.ID), "application.log"+suffix)
		target := filepath.Join(dir, v.ID+".log"+suffix)
		if e := os.Link(source, target); e != nil && !os.IsNotExist(e) && !os.IsExist(e) {
			return e
		}
	}
	if e := fsutil.JSON(filepath.Join(dir, v.ID+".json"), result{Exit: *exit, ID: v.ID, Name: v.Name}); e != nil {
		return e
	}
	d.pruneResultsLocked(time.Now())
	return nil
}
func (d *Daemon) findResult(id string) (result, error) {
	var found result
	if !api.ValidName(id) {
		return found, state.ErrNotFound
	}
	d.resultMu.Lock()
	defer d.resultMu.Unlock()
	now := time.Now()
	d.pruneResultsLocked(now)
	entries, e := os.ReadDir(filepath.Join(d.Config.Root, "results"))
	if e != nil {
		return found, state.ErrNotFound
	}
	matches := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, e := entry.Info()
		if e != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) >= resultRetention {
			continue
		}
		var v result
		if fsutil.ReadJSON(filepath.Join(d.Config.Root, "results", entry.Name()), &v) != nil {
			continue
		}
		if v.ID == id || v.Name == id {
			return v, nil
		}
		if strings.HasPrefix(v.ID, id) {
			found = v
			matches++
		}
	}
	if matches == 1 {
		return found, nil
	}
	if matches > 1 {
		return found, fmt.Errorf("ambiguous removed container ID")
	}
	return found, state.ErrNotFound
}
func (d *Daemon) pruneResults() {
	d.resultMu.Lock()
	defer d.resultMu.Unlock()
	d.pruneResultsLocked(time.Now())
}
func (d *Daemon) pruneResultsLocked(now time.Time) {
	dir := filepath.Join(d.Config.Root, "results")
	entries, e := os.ReadDir(dir)
	if e != nil {
		return
	}
	type saved struct {
		id   string
		at   time.Time
		size int64
	}
	var all []saved
	var total int64
	for _, p := range entries {
		if !strings.HasSuffix(p.Name(), ".json") {
			continue
		}
		info, e := p.Info()
		if e != nil {
			continue
		}
		id := strings.TrimSuffix(p.Name(), ".json")
		n := info.Size()
		for _, ext := range []string{".log", ".log.1"} {
			if st, e := os.Stat(filepath.Join(dir, id+ext)); e == nil {
				n += st.Size()
			}
		}
		all = append(all, saved{id, info.ModTime(), n})
		total += n
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for i, v := range all {
		if now.Sub(v.at) < resultRetention && total <= 256<<20 && len(all)-i <= 128 {
			break
		}
		for _, ext := range []string{".json", ".log", ".log.1"} {
			os.Remove(filepath.Join(dir, v.id+ext))
		}
		total -= v.size
	}
}
func (d *Daemon) retainedAttach(ctx context.Context, id string, s *wire.Stream) error {
	v, e := d.Store.Get(id)
	var exit *api.Exit
	var path string
	if e == nil {
		if v.Exit == nil {
			return fmt.Errorf("container has no retained exit status")
		}
		exit = v.Exit
		path = filepath.Join(d.dir(v.ID), "application.log")
	} else {
		r, e := d.findResult(id)
		if e != nil {
			return e
		}
		exit = &r.Exit
		path = filepath.Join(d.Config.Root, "results", r.ID+".log")
	}
	j := journal.Open(path)
	var seq uint64
	for {
		frames := j.Read(seq)
		if len(frames) == 0 {
			break
		}
		for _, f := range frames {
			if e = s.Send(f); e != nil {
				return e
			}
			seq = f.Sequence
		}
	}
	if exit.Code == nil {
		return fmt.Errorf("%s", exit.Reason)
	}
	return s.Send(api.Frame{Type: "exit", Code: exit.Code, Message: exit.Reason})
}
