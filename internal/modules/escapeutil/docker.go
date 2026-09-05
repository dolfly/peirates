package escapeutil

import (
	"net/url"
	"path/filepath"
	"strings"
)

// DockerSocketPaths returns absolute Unix socket paths from an explicit list,
// a unix:// DOCKER_HOST value, and Docker's conventional locations. TCP,
// SSH, malformed, and relative endpoints are deliberately ignored.
func DockerSocketPaths(dockerHost string, explicit []string) []string {
	paths := append([]string(nil), explicit...)
	if dockerHost != "" {
		parsed, err := url.Parse(dockerHost)
		if err == nil && parsed.Scheme == "unix" && parsed.Host == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
			paths = append(paths, parsed.Path)
		}
	}
	paths = append(paths, "/var/run/docker.sock", "/run/docker.sock")
	var cleaned []string
	for _, path := range paths {
		if strings.HasPrefix(path, "unix://") {
			parsed, err := url.Parse(path)
			if err != nil || parsed.Scheme != "unix" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				continue
			}
			path = parsed.Path
		}
		if !filepath.IsAbs(path) || hasControlCharacter(path) {
			continue
		}
		cleaned = append(cleaned, filepath.Clean(path))
	}
	return SortedUnique(cleaned)
}

func hasControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
