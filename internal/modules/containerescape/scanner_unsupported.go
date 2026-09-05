//go:build !linux

package containerescape

import (
	"context"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
)

func scanPlatform(ctx context.Context, _ Options) ([]escapeutil.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return unsupportedFindings(), nil
}
