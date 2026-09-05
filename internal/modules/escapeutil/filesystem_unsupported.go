//go:build !linux

package escapeutil

import "os"

// PathIdentity reports that Linux filesystem identity inspection is unavailable.
func PathIdentity(string) (FileIdentity, error) { return FileIdentity{}, ErrUnsupported }

// OpenDirectoryNoFollow reports that safe Linux directory opening is unavailable.
func OpenDirectoryNoFollow(string) (*os.File, FileIdentity, error) {
	return nil, FileIdentity{}, ErrUnsupported
}
