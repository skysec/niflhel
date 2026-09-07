package journal

import (
	"io"
	"os"
)

// Sink writes raw diagnostic output with at most two Limit-byte files. It is
// used by a separate host helper so VMM logging survives daemon restarts.
func Sink(path string, r io.Reader) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer func() { f.Close() }()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	size := st.Size()
	buf := make([]byte, 32<<10)
	for {
		n, re := r.Read(buf)
		if n > 0 {
			if size+int64(n) > Limit {
				if e = f.Close(); e != nil {
					return e
				}
				if e = os.Remove(path + ".1"); e != nil && !os.IsNotExist(e) {
					return e
				}
				if e = os.Rename(path, path+".1"); e != nil {
					return e
				}
				f, e = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if e != nil {
					return e
				}
				size = 0
			}
			if _, e = f.Write(buf[:n]); e != nil {
				return e
			}
			size += int64(n)
		}
		if re == io.EOF {
			return f.Sync()
		}
		if re != nil {
			return re
		}
	}
}
