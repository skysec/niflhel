package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"niflhel/internal/api"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func Open(path string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS sandboxes(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,body BLOB NOT NULL); CREATE TABLE IF NOT EXISTS volumes(name TEXT PRIMARY KEY,body BLOB NOT NULL); CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL,action TEXT NOT NULL,at TEXT NOT NULL);")
	if e != nil {
		db.Close()
		return nil, e
	}
	os.Chmod(path, 0600)
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) List() ([]api.Sandbox, error) {
	rows, e := s.db.Query("SELECT body FROM sandboxes ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []api.Sandbox{}
	for rows.Next() {
		var b []byte
		var v api.Sandbox
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &v); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) Get(id string) (api.Sandbox, error) {
	all, e := s.List()
	if e != nil {
		return api.Sandbox{}, e
	}
	for _, v := range all {
		if v.ID == id || v.Name == id {
			return v, nil
		}
	}
	var found []api.Sandbox
	for _, v := range all {
		if id != "" && strings.HasPrefix(v.ID, id) {
			found = append(found, v)
		}
	}
	if len(found) == 1 {
		return found[0], nil
	}
	if len(found) > 1 {
		return api.Sandbox{}, fmt.Errorf("%w: ambiguous ID", ErrConflict)
	}
	return api.Sandbox{}, ErrNotFound
}
func (s *Store) Create(v api.Sandbox) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO sandboxes VALUES(?,?,?)", v.ID, v.Name, b); e != nil {
		return fmt.Errorf("%w: name/ID already exists: %v", ErrConflict, e)
	}
	if _, e = tx.Exec("INSERT INTO events(id,action,at) VALUES(?,?,?)", v.ID, "create", time.Now().UTC().Format(time.RFC3339Nano)); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Update(id string, fn func(*api.Sandbox) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var b []byte
	if e = tx.QueryRow("SELECT body FROM sandboxes WHERE id=?", id).Scan(&b); e != nil {
		return e
	}
	var v api.Sandbox
	if e = json.Unmarshal(b, &v); e != nil {
		return e
	}
	if e = fn(&v); e != nil {
		return e
	}
	v.Updated = time.Now().UTC()
	b, e = json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE sandboxes SET body=? WHERE id=?", b, id); e != nil {
		return e
	}
	return tx.Commit()
}

var transitions = map[string][]string{
	"creating": {"created", "failed", "removing"}, "created": {"starting", "removing"}, "starting": {"running", "failed", "stopping"},
	"running": {"stopping", "failed"}, "stopping": {"exited", "failed"}, "exited": {"starting", "removing"}, "failed": {"removing"}, "removing": {},
}

func Transition(v *api.Sandbox, to, reason string) error {
	if v.State == to {
		return nil
	}
	for _, state := range transitions[v.State] {
		if state == to {
			v.State = to
			v.Reason = reason
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition %s to %s", ErrConflict, v.State, to)
}
func (s *Store) Intent(id, action string) error {
	_, e := s.db.Exec("INSERT INTO events(id,action,at) VALUES(?,?,?)", id, action, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) Delete(id string) error {
	_, e := s.db.Exec("DELETE FROM sandboxes WHERE id=?", id)
	return e
}
func (s *Store) Volumes() ([]api.Volume, error) {
	rows, e := s.db.Query("SELECT body FROM volumes ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []api.Volume{}
	for rows.Next() {
		var b []byte
		var v api.Volume
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &v); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) PutVolume(v api.Volume) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = s.db.Exec("INSERT INTO volumes VALUES(?,?)", v.Name, b)
	return e
}
func (s *Store) Volume(name string) (api.Volume, error) {
	var b []byte
	var v api.Volume
	e := s.db.QueryRow("SELECT body FROM volumes WHERE name=?", name).Scan(&b)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	return v, e
}
func (s *Store) DeleteVolume(name string) error {
	_, e := s.db.Exec("DELETE FROM volumes WHERE name=?", name)
	return e
}
