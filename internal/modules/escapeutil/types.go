// Package escapeutil provides read-only parsing and filesystem helpers shared
// by container-escape assessment modules.
package escapeutil

import (
	"errors"
	"fmt"
	"sort"
)

// ErrUnsupported is returned when an operating system cannot provide a
// Linux-specific container assessment primitive.
var ErrUnsupported = errors.New("container escape assessment is supported only on Linux")

// Status describes how completely a technique's observable prerequisites are
// satisfied. A candidate still requires a mutating action to prove viability.
type Status string

const (
	StatusAvailable   Status = "available"
	StatusCandidate   Status = "candidate"
	StatusBlocked     Status = "blocked"
	StatusUnsupported Status = "unsupported"
)

// Finding is one read-only assessment result. Evidence must describe only the
// checked prerequisites; callers must not treat it as proof of an escape.
type Finding struct {
	Technique string
	Status    Status
	Summary   string
	Evidence  []string
}

// FileIdentity identifies a filesystem object without exposing its contents.
type FileIdentity struct {
	Device uint64
	Inode  uint64
}

// Equal reports whether two identities refer to the same filesystem object.
func (identity FileIdentity) Equal(other FileIdentity) bool {
	return identity == other
}

// CgroupEntry describes one line from /proc/self/cgroup.
type CgroupEntry struct {
	HierarchyID int
	Controllers []string
	Path        string
}

// CgroupInfo describes whether a process is in cgroup v2's unified hierarchy
// and records its non-sensitive controller mappings.
type CgroupInfo struct {
	Unified bool
	Entries []CgroupEntry
}

// ControllerPath returns the process cgroup path for a v1 controller.
func (info CgroupInfo) ControllerPath(controller string) (string, bool) {
	for _, entry := range info.Entries {
		for _, candidate := range entry.Controllers {
			if candidate == controller {
				return entry.Path, true
			}
		}
	}
	return "", false
}

// SortedUnique returns non-empty strings in deterministic order.
func SortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// ValidateFinding rejects incomplete or invalid scanner output.
func ValidateFinding(finding Finding) error {
	if finding.Technique == "" {
		return fmt.Errorf("finding technique is empty")
	}
	if finding.Summary == "" {
		return fmt.Errorf("finding summary is empty")
	}
	switch finding.Status {
	case StatusAvailable, StatusCandidate, StatusBlocked, StatusUnsupported:
		return nil
	default:
		return fmt.Errorf("finding %s has invalid status %q", finding.Technique, finding.Status)
	}
}
