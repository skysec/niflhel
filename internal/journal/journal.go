package journal

import (
	"bufio"
	"encoding/json"
	"niflhel/internal/api"
	"os"
	"sync"
	"time"
)

const Limit = 8 << 20

type Journal struct {
	mu     sync.Mutex
	Path   string
	frames []api.Frame
	bytes  int
	seq    uint64
}

func Open(path string) *Journal {
	j := &Journal{Path: path}
	for _, p := range []string{path + ".1", path} {
		f, e := os.Open(p)
		if e != nil {
			continue
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 4096), 1<<20)
		for s.Scan() {
			var frame api.Frame
			if json.Unmarshal(s.Bytes(), &frame) == nil {
				j.append(frame)
				if frame.Sequence > j.seq {
					j.seq = frame.Sequence
				}
			}
		}
		f.Close()
	}
	return j
}
func (j *Journal) append(f api.Frame) {
	j.frames = append(j.frames, f)
	j.bytes += len(f.Data) + 128
	for j.bytes > Limit && len(j.frames) > 1 {
		j.bytes -= len(j.frames[0].Data) + 128
		j.frames = j.frames[1:]
	}
}
func (j *Journal) Write(kind string, b []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for len(b) > 0 {
		n := len(b)
		if n > 32<<10 {
			n = 32 << 10
		}
		j.seq++
		f := api.Frame{Type: kind, Data: append([]byte{}, b[:n]...), Sequence: j.seq, Time: time.Now().UTC()}
		b = b[n:]
		j.append(f)
		if j.Path != "" {
			info, _ := os.Stat(j.Path)
			if info != nil && info.Size() > Limit {
				os.Remove(j.Path + ".1")
				if e := os.Rename(j.Path, j.Path+".1"); e != nil {
					return e
				}
			}
			file, e := os.OpenFile(j.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if e != nil {
				return e
			}
			e = json.NewEncoder(file).Encode(f)
			file.Close()
			if e != nil {
				return e
			}
		}
	}
	return nil
}
func (j *Journal) Read(after uint64) []api.Frame {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := []api.Frame{}
	if len(j.frames) > 0 && after+1 < j.frames[0].Sequence {
		out = append(out, api.Frame{Type: "gap", Message: "older application logs were rotated", Sequence: j.frames[0].Sequence - 1})
	}
	size := 0
	for _, f := range j.frames {
		if f.Sequence > after {
			out = append(out, f)
			size += len(f.Data)
			if size >= 256<<10 {
				break
			}
		}
	}
	return out
}

type Writer struct {
	J    *Journal
	Kind string
}

func (w Writer) Write(b []byte) (int, error) { e := w.J.Write(w.Kind, b); return len(b), e }
