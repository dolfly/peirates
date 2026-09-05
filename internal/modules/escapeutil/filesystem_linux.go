//go:build linux

package escapeutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// PathIdentity returns the followed path's device and inode identity.
func PathIdentity(path string) (FileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return FileIdentity{}, err
	}
	return identityFromStat(stat), nil
}

// OpenDirectoryNoFollow opens an existing absolute directory without following
// symlinks in any path component and returns both a closeable descriptor and
// its identity. Callers retain ownership of the returned file.
func OpenDirectoryNoFollow(path string) (*os.File, FileIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, FileIdentity{}, fmt.Errorf("directory path must be absolute and normalized")
	}

	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		nextFD, openErr := unix.Openat(fd, component, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, FileIdentity{}, openErr
		}
		fd = nextFD
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, FileIdentity{}, fmt.Errorf("inspect opened directory: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, FileIdentity{}, fmt.Errorf("construct directory file")
	}
	return file, identityFromStat(stat), nil
}

func identityFromStat(stat unix.Stat_t) FileIdentity {
	return FileIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}
}
