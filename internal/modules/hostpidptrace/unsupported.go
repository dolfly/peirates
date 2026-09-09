//go:build !linux || !amd64

package hostpidptrace

import (
	"context"
	"io"
)

func probePlatform(context.Context) (ProbeResult, error) { return ProbeResult{}, ErrUnsupported }

func launchWorker(context.Context, RunOptions) (Result, error) { return Result{}, ErrUnsupported }

func runWorker(io.Reader, io.Writer) error { return ErrUnsupported }
