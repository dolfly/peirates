package escapeutil

import (
	"reflect"
	"testing"
)

func TestDockerSocketPaths(t *testing.T) {
	tests := []struct {
		name       string
		dockerHost string
		explicit   []string
		want       []string
	}{
		{
			name:       "unix host and explicit",
			dockerHost: "unix:///custom/docker.sock",
			explicit:   []string{"/explicit/docker.sock", "unix:///second/docker.sock", "relative", "/run/docker.sock"},
			want:       []string{"/custom/docker.sock", "/explicit/docker.sock", "/run/docker.sock", "/second/docker.sock", "/var/run/docker.sock"},
		},
		{
			name:       "reject remote host",
			dockerHost: "tcp://127.0.0.1:2375",
			want:       []string{"/run/docker.sock", "/var/run/docker.sock"},
		},
		{
			name:       "reject authority query and fragment",
			dockerHost: "unix://server/path?x=1#fragment",
			explicit:   []string{"unix://server/path", "unix:///ok.sock?x=1"},
			want:       []string{"/run/docker.sock", "/var/run/docker.sock"},
		},
		{
			name:     "reject control characters",
			explicit: []string{"/bad\npath", "/bad\tpath"},
			want:     []string{"/run/docker.sock", "/var/run/docker.sock"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DockerSocketPaths(test.dockerHost, test.explicit); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("DockerSocketPaths() = %#v, want %#v", got, test.want)
			}
		})
	}
}
