//go:build linux

package escapeutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDirectoryNoFollow(t *testing.T) {
	directory := t.TempDir()
	identity, err := PathIdentity(directory)
	if err != nil {
		t.Fatal(err)
	}
	file, openedIdentity, err := OpenDirectoryNoFollow(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !openedIdentity.Equal(identity) {
		t.Fatalf("opened identity = %#v, want %#v", openedIdentity, identity)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(directory, symlink); err != nil {
		t.Fatal(err)
	}
	if file, _, err := OpenDirectoryNoFollow(symlink); err == nil {
		_ = file.Close()
		t.Fatal("OpenDirectoryNoFollow(symlink) unexpectedly succeeded")
	}

	intermediateRoot := t.TempDir()
	intermediateLink := filepath.Join(intermediateRoot, "link")
	if err := os.Symlink(filepath.Dir(directory), intermediateLink); err != nil {
		t.Fatal(err)
	}
	throughIntermediateLink := filepath.Join(intermediateLink, filepath.Base(directory))
	if file, _, err := OpenDirectoryNoFollow(throughIntermediateLink); err == nil {
		_ = file.Close()
		t.Fatal("OpenDirectoryNoFollow(path through symlink) unexpectedly succeeded")
	}

	regularFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(regularFile, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if file, _, err := OpenDirectoryNoFollow(regularFile); err == nil {
		_ = file.Close()
		t.Fatal("OpenDirectoryNoFollow(file) unexpectedly succeeded")
	}

	for _, path := range []string{"relative", directory + "/."} {
		if file, _, err := OpenDirectoryNoFollow(path); err == nil {
			_ = file.Close()
			t.Fatalf("OpenDirectoryNoFollow(%q) unexpectedly succeeded", path)
		}
	}
}
