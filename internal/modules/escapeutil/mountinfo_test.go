package escapeutil

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseMountInfo(t *testing.T) {
	data := "36 25 0:32 /docker\\040root /host\\040root rw,nosuid shared:7 - ext4 /dev/sda1 rw,relatime\n" +
		"37 25 0:33 / / rw - overlay overlay rw,lowerdir=/lower,upperdir=/host\\134upper,workdir=/work\n"
	mounts, err := ParseMountInfo([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("mount count = %d, want 2", len(mounts))
	}
	first := mounts[0]
	if first.ID != 36 || first.ParentID != 25 || first.Root != "/docker root" || first.MountPoint != "/host root" || first.Source != "/dev/sda1" {
		t.Fatalf("first mount = %#v", first)
	}
	if !reflect.DeepEqual(first.OptionalFields, []string{"shared:7"}) {
		t.Fatalf("optional fields = %#v", first.OptionalFields)
	}
	if got := OverlayUpperDirs(mounts); !reflect.DeepEqual(got, []string{"/host\\upper"}) {
		t.Fatalf("OverlayUpperDirs() = %#v", got)
	}
}

func TestParseMountInfoRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "short", line: "1 2 3", want: "malformed mountinfo"},
		{name: "id", line: "x 2 0:1 / / rw - ext4 /dev/a rw", want: "mount ID"},
		{name: "parent", line: "1 x 0:1 / / rw - ext4 /dev/a rw", want: "parent mount ID"},
		{name: "truncated escape", line: "1 2 0:1 / /bad\\ rw - ext4 /dev/a rw", want: "truncated mount escape"},
		{name: "unknown escape", line: "1 2 0:1 / /bad\\777 rw - ext4 /dev/a rw", want: "unsupported mount escape"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseMountInfo([]byte(test.line + "\n"))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseMountInfo() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMountSelections(t *testing.T) {
	mounts := []Mount{
		{Root: "/", MountPoint: "/", FSType: "overlay", SuperOptions: []string{"upperdir=/host/upper"}},
		{Root: "/", MountPoint: "/host", FSType: "ext4"},
		{Root: "/", MountPoint: "/host", FSType: "ext4"},
		{Root: "/subdir", MountPoint: "/not-root", FSType: "ext4"},
		{Root: "/", MountPoint: "/proc", FSType: "proc"},
		{Root: "/", MountPoint: "relative", FSType: "ext4"},
		{Root: "/", MountPoint: "/overlay", FSType: "overlay", SuperOptions: []string{"upperdir=relative", "upperdir=/host/second"}},
	}
	if got := HostRootCandidates(mounts); !reflect.DeepEqual(got, []string{"/host", "/overlay"}) {
		t.Fatalf("HostRootCandidates() = %#v", got)
	}
	if got := OverlayUpperDirs(mounts); !reflect.DeepEqual(got, []string{"/host/second", "/host/upper"}) {
		t.Fatalf("OverlayUpperDirs() = %#v", got)
	}
	if got := MountsByType(mounts, "proc"); len(got) != 1 || got[0].MountPoint != "/proc" {
		t.Fatalf("MountsByType(proc) = %#v", got)
	}
}

func TestOutermostPaths(t *testing.T) {
	paths := []string{
		"/hostroot/run/container/rootfs",
		"/second",
		"/hostroot",
		"/second-nested",
		"/second/var/lib/rootfs",
		"/hostroot",
	}
	want := []string{"/hostroot", "/second", "/second-nested"}
	if got := OutermostPaths(paths); !reflect.DeepEqual(got, want) {
		t.Fatalf("OutermostPaths() = %#v, want %#v", got, want)
	}
}
