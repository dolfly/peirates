//go:build !linux

package hostproc

import (
	"context"
	"fmt"
	"io"
)

func probe(context.Context, normalizedOptions) (Finding, error) {
	return Finding{}, ErrUnsupported
}

func launch(context.Context, normalizedOptions) error {
	return ErrUnsupported
}

func runCrashWorker(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "%s internal crash worker does not accept arguments\n", outputPrefix)
		return 2
	}
	fmt.Fprintln(stderr, outputPrefix, ErrUnsupported)
	return 1
}
