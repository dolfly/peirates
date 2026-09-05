//go:build !linux

package dockersocket

import (
	"context"
	"fmt"
)

func probe(_ context.Context, _ Options) (Finding, error) {
	return Finding{}, ErrUnsupported
}

func launch(_ context.Context, _ Options) error {
	return fmt.Errorf("%w", ErrUnsupported)
}
