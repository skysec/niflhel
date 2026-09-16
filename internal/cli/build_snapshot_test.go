package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"niflhel/internal/filecopy"
)

func snapshotKey(t *testing.T) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "publisher.key")
	writeSnapshotFile(t, name, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, ed25519.PrivateKeySize)))
	return name
}

func writeSnapshotFile(t *testing.T, name, data string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBuildTempCleanupReadOnlyDirectories(t *testing.T) {
	stage, err := privateBuildTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeBuildTemp(stage) })
	dir := filepath.Join(stage, "readonly")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeSnapshotFile(t, filepath.Join(dir, "file"), "safe")
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	if err := removeBuildTemp(stage); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("snapshot not removed", err)
	}
}

// The child runs at the precise old TOCTOU boundary: after preparation but
// before consuming either --local. It swaps one root and adds a key hard link
// in the other. Only the exported files are recorded, using a non-secret key.
func TestBaseBuildExportsSnapshotsAfterRootRebinding(t *testing.T) {
	for _, rebound := range []string{"context", "dockerfile"} {
		t.Run(rebound, func(t *testing.T) {
			contextDir, dockerfileDir := t.TempDir(), t.TempDir()
			writeSnapshotFile(t, filepath.Join(contextDir, "input"), "safe context\n")
			writeSnapshotFile(t, filepath.Join(dockerfileDir, "Dockerfile"), "FROM scratch\n")
			key := snapshotKey(t)
			bin, record := t.TempDir(), filepath.Join(t.TempDir(), "exported")
			script := `#!/bin/sh
set -eu
for arg do
  case "$arg" in
    context=*) context=${arg#context=} ;;
    dockerfile=*) dockerfile=${arg#dockerfile=} ;;
  esac
done
test "$context" != "$SOURCE_CONTEXT"
test "$dockerfile" != "$SOURCE_DOCKERFILE"
mv "$REBIND" "$REBIND.before"
ln -s "$KEY_DIR" "$REBIND"
ln "$KEY_FILE" "$ALIAS_ROOT/late.key"
find "$context" "$dockerfile" -type f -exec cat {} \; > "$RECORD"
printf '%s\n' "$context" "$dockerfile" > "$RECORD.paths"
exit 23
`
			stub := filepath.Join(bin, "buildctl")
			writeSnapshotFile(t, stub, script)
			if err := os.Chmod(stub, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			t.Setenv("BUILDKIT_HOST", "unix:///unused-buildkit.sock")
			t.Setenv("NIFLHEL_BASE_PACKAGER", "/unused-packager")
			t.Setenv("SOURCE_CONTEXT", contextDir)
			t.Setenv("SOURCE_DOCKERFILE", dockerfileDir)
			t.Setenv("KEY_DIR", filepath.Dir(key))
			t.Setenv("KEY_FILE", key)
			t.Setenv("RECORD", record)
			original, aliasRoot := contextDir, dockerfileDir
			if rebound == "dockerfile" {
				original, aliasRoot = dockerfileDir, contextDir
			}
			t.Setenv("REBIND", original)
			t.Setenv("ALIAS_ROOT", aliasRoot)
			t.Cleanup(func() { os.RemoveAll(original + ".before") })
			// An attacker-selected temp parent must not receive staging data.
			unsafeTemp := t.TempDir()
			t.Setenv("TMPDIR", unsafeTemp)
			var output bytes.Buffer
			cmd := New(strings.NewReader(""), &output, &output)
			cmd.SetArgs([]string{"base", "build", "-t", "test/base", "-f", filepath.Join(dockerfileDir, "Dockerfile"), "--signing-key", key, "--key-id", "test", "--firecracker-version", "1.16.1", contextDir})
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "exit status 23") {
				t.Fatalf("did not reach fake BuildKit: %v (%s)", err, &output)
			}
			data, err := os.ReadFile(record)
			if err != nil || string(data) != "safe context\nFROM scratch\n" {
				t.Fatalf("unexpected exported bytes: %q, %v", data, err)
			}
			paths, err := os.ReadFile(record + ".paths")
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range strings.Fields(string(paths)) {
				if strings.HasPrefix(path, unsafeTemp) {
					t.Fatal("staged beneath untrusted TMPDIR")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("snapshot not cleaned up: %s: %v", path, err)
				}
			}
		})
	}
}

func TestBuildSnapshotChecksOpenedEntryAfterEnumeration(t *testing.T) {
	key := snapshotKey(t)
	keyInfo, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	root, stage := t.TempDir(), t.TempDir()
	stageInfo, err := os.Stat(stage)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "innocent")
	writeSnapshotFile(t, name, "safe")
	source, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	entries, err := source.ReadDir(-1)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, name); err != nil {
		t.Fatal(err)
	}
	s := buildSnapshot{key: keyInfo, stage: stageInfo}
	dest := filepath.Join(stage, "copy")
	if err := s.copyEntry(source, entries[0].Name(), dest, 0); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("accepted key substituted after directory enumeration: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("key copied before alias rejection", err)
	}
}

func TestBuildSnapshotPinsSourceDirectory(t *testing.T) {
	parent, stage, key := t.TempDir(), t.TempDir(), snapshotKey(t)
	root := filepath.Join(parent, "context")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	writeSnapshotFile(t, filepath.Join(root, "input"), "safe")
	source, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := os.Rename(root, root+".before"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(key), root); err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	stageInfo, err := os.Stat(stage)
	if err != nil {
		t.Fatal(err)
	}
	s := buildSnapshot{key: keyInfo, stage: stageInfo}
	if err := s.copyDir(source, stage, 0); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(stage)
	if err != nil || len(entries) != 1 || entries[0].Name() != "input" {
		t.Fatalf("copied replacement directory: %v, %v", entries, err)
	}
}

func TestBaseBuildSnapshotFileTypesAndBounds(t *testing.T) {
	for _, kind := range []string{"regular", "relative link", "absolute link", "escaping link", "dangling link", "cycle", "fifo", "oversize", "entries", "depth"} {
		t.Run(kind, func(t *testing.T) {
			root, stage, key := t.TempDir(), t.TempDir(), snapshotKey(t)
			if err := os.Chmod(root, 0750); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, "input")
			writeSnapshotFile(t, file, "safe")
			if err := os.Chmod(file, 0751); err != nil {
				t.Fatal(err)
			}
			link := ""
			switch kind {
			case "relative link":
				link = "input"
			case "absolute link":
				link = key
			case "escaping link":
				link, _ = filepath.Rel(root, key)
			case "dangling link":
				link = "missing"
			case "cycle":
				link = "link"
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(file, filecopy.MaxBytes+1); err != nil {
					t.Fatal(err)
				}
			case "entries":
				for i := range 10000 {
					writeSnapshotFile(t, filepath.Join(root, fmt.Sprint(i)), "")
				}
			case "depth":
				if err := os.MkdirAll(filepath.Join(root, strings.Repeat("d/", 129)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if link != "" {
				if err := os.Symlink(link, filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			}
			gotKey, roots, err := prepareBaseBuild(key, stage, root)
			if kind != "regular" && kind != "relative link" {
				if err == nil {
					t.Fatal("unsafe snapshot accepted")
				}
				return
			}
			if err != nil || len(gotKey) != ed25519.PrivateKeySize {
				t.Fatal(err)
			}
			rootInfo, err := os.Stat(roots[0])
			if err != nil || rootInfo.Mode().Perm() != 0750 {
				t.Fatal("local root mode not preserved", err)
			}
			copy := filepath.Join(roots[0], "input")
			info, err := os.Stat(copy)
			if err != nil || info.Mode().Perm() != 0751 {
				t.Fatal("executable mode not preserved", err)
			}
			// Writes to the original must not affect the snapshot's inode.
			writeSnapshotFile(t, file, "changed")
			data, err := os.ReadFile(copy)
			if err != nil || string(data) != "safe" {
				t.Fatal("snapshot retained mutable source", err)
			}
			if kind == "relative link" {
				data, err := os.ReadFile(filepath.Join(roots[0], "link"))
				if err != nil || string(data) != "safe" {
					t.Fatal("internal symlink changed", err)
				}
			}
		})
	}
}
