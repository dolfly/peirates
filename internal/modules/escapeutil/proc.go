package escapeutil

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// ParseEffectiveCapabilities parses CapEff from a Linux proc status file.
func ParseEffectiveCapabilities(status []byte) (uint64, error) {
	fields, err := procStatusField(status, "CapEff")
	if err != nil {
		return 0, err
	}
	if len(fields) != 1 {
		return 0, fmt.Errorf("malformed CapEff value")
	}
	capabilities, err := strconv.ParseUint(fields[0], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed CapEff value: %w", err)
	}
	return capabilities, nil
}

// ParseEffectiveUID parses the effective UID (the second value on the Uid
// line) from a Linux proc status file.
func ParseEffectiveUID(status []byte) (int, error) {
	fields, err := procStatusField(status, "Uid")
	if err != nil {
		return 0, err
	}
	if len(fields) != 4 {
		return 0, fmt.Errorf("malformed Uid value")
	}
	uid, err := strconv.ParseUint(fields[1], 10, 31)
	if err != nil {
		return 0, fmt.Errorf("malformed effective Uid value: %w", err)
	}
	return int(uid), nil
}

func procStatusField(status []byte, name string) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(status)))
	for scanner.Scan() {
		line := scanner.Text()
		separator := strings.IndexByte(line, ':')
		if separator < 0 || line[:separator] != name {
			continue
		}
		return strings.Fields(line[separator+1:]), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s from process status: %w", name, err)
	}
	return nil, fmt.Errorf("%s is missing from process status", name)
}

// HasCapability reports whether the numbered Linux capability is effective.
func HasCapability(capabilities uint64, capability int) bool {
	if capability < 0 || capability >= 64 {
		return false
	}
	return capabilities&(uint64(1)<<uint(capability)) != 0
}

// ParseCgroups parses /proc/self/cgroup without inspecting any cgroup files.
func ParseCgroups(data []byte) (CgroupInfo, error) {
	var result CgroupInfo
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return CgroupInfo{}, fmt.Errorf("malformed cgroup line %d", lineNumber)
		}
		hierarchyID, err := strconv.Atoi(parts[0])
		if err != nil || hierarchyID < 0 {
			return CgroupInfo{}, fmt.Errorf("malformed cgroup hierarchy on line %d", lineNumber)
		}
		if !strings.HasPrefix(parts[2], "/") {
			return CgroupInfo{}, fmt.Errorf("non-absolute cgroup path on line %d", lineNumber)
		}
		controllers := []string(nil)
		if parts[1] != "" {
			controllers = strings.Split(parts[1], ",")
			for _, controller := range controllers {
				if controller == "" {
					return CgroupInfo{}, fmt.Errorf("empty cgroup controller on line %d", lineNumber)
				}
			}
		}
		if hierarchyID == 0 && len(controllers) == 0 {
			result.Unified = true
		}
		result.Entries = append(result.Entries, CgroupEntry{
			HierarchyID: hierarchyID,
			Controllers: append([]string(nil), controllers...),
			Path:        parts[2],
		})
	}
	if err := scanner.Err(); err != nil {
		return CgroupInfo{}, fmt.Errorf("read process cgroups: %w", err)
	}
	if len(result.Entries) == 0 {
		return CgroupInfo{}, fmt.Errorf("process cgroup data is empty")
	}
	return result, nil
}
