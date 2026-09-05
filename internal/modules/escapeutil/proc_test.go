package escapeutil

import (
	"strings"
	"testing"
)

func TestParseEffectiveCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		want    uint64
		wantErr string
	}{
		{name: "value", status: "Name:\tpeirates\nCapEff:\t0000000000240000\n", want: 0x240000},
		{name: "missing", status: "Name:\tpeirates\n", wantErr: "CapEff is missing"},
		{name: "missing value", status: "CapEff:\n", wantErr: "malformed CapEff"},
		{name: "extra value", status: "CapEff: 1 2\n", wantErr: "malformed CapEff"},
		{name: "invalid hex", status: "CapEff:\tnot-hex\n", wantErr: "malformed CapEff"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseEffectiveCapabilities([]byte(test.status))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("ParseEffectiveCapabilities() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("ParseEffectiveCapabilities() = %#x, %v; want %#x", got, err, test.want)
			}
		})
	}
}

func TestParseEffectiveUID(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		want    int
		wantErr string
	}{
		{name: "value", status: "Uid:\t1000\t2000\t3000\t4000\n", want: 2000},
		{name: "missing", status: "Name: test\n", wantErr: "Uid is missing"},
		{name: "short", status: "Uid: 1 2\n", wantErr: "malformed Uid"},
		{name: "invalid", status: "Uid: 1 nope 3 4\n", wantErr: "malformed effective Uid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseEffectiveUID([]byte(test.status))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("ParseEffectiveUID() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("ParseEffectiveUID() = %d, %v; want %d", got, err, test.want)
			}
		})
	}
}

func TestHasCapability(t *testing.T) {
	if !HasCapability(1<<21, 21) {
		t.Fatal("set capability was not found")
	}
	for _, capability := range []int{-1, 20, 64} {
		if HasCapability(1<<21, capability) {
			t.Fatalf("capability %d unexpectedly found", capability)
		}
	}
}

func TestParseCgroups(t *testing.T) {
	v1, err := ParseCgroups([]byte("5:memory,cpu:/workload\n4:devices:/\n"))
	if err != nil || v1.Unified || len(v1.Entries) != 2 {
		t.Fatalf("ParseCgroups(v1) = %#v, %v", v1, err)
	}
	if path, ok := v1.ControllerPath("cpu"); !ok || path != "/workload" {
		t.Fatalf("ControllerPath(cpu) = %q, %v", path, ok)
	}
	v2, err := ParseCgroups([]byte("0::/workload\n"))
	if err != nil || !v2.Unified {
		t.Fatalf("ParseCgroups(v2) = %#v, %v", v2, err)
	}
	for _, malformed := range []string{"", "bad", "x:cpu:/", "1:cpu:relative", "1:cpu,:/"} {
		if _, err := ParseCgroups([]byte(malformed)); err == nil {
			t.Fatalf("ParseCgroups(%q) unexpectedly succeeded", malformed)
		}
	}
}
