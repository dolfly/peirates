//go:build !linux

package hostroot

import (
	"fmt"
	"io"
	"os"
)

// Launch reports that host-root entry is unavailable on this platform.
func Launch(_ io.Reader, _, _ io.Writer) error { return ErrUnsupported }

// LaunchAt reports that host-root entry is unavailable on this platform.
func LaunchAt(_ string, _ io.Reader, _, _ io.Writer) error { return ErrUnsupported }

// RunWorker reports that the private worker cannot run on this platform.
func RunWorker(args []string, _, _, stderr *os.File) int {
	if len(args) != 3 {
		fmt.Fprintf(stderr, "%s internal worker requires a target path, device, and inode\n", outputPrefix)
		return 2
	}
	fmt.Fprintf(stderr, "%s %v\n", outputPrefix, ErrUnsupported)
	return 1
}
