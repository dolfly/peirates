package escapeutil

import "testing"

func TestValidateFinding(t *testing.T) {
	valid := Finding{Technique: "hostroot-breakout", Status: StatusCandidate, Summary: "candidate"}
	if err := ValidateFinding(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Finding{
		{Status: StatusBlocked, Summary: "missing technique"},
		{Technique: "test", Status: StatusBlocked},
		{Technique: "test", Status: "unknown", Summary: "bad status"},
	} {
		if err := ValidateFinding(invalid); err == nil {
			t.Fatalf("ValidateFinding(%#v) unexpectedly succeeded", invalid)
		}
	}
}

func TestFileIdentityAndSortedUnique(t *testing.T) {
	if !(FileIdentity{Device: 1, Inode: 2}).Equal(FileIdentity{Device: 1, Inode: 2}) {
		t.Fatal("matching identities differ")
	}
	if (FileIdentity{Device: 1, Inode: 2}).Equal(FileIdentity{Device: 1, Inode: 3}) {
		t.Fatal("different identities match")
	}
	got := SortedUnique([]string{"b", "", "a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("SortedUnique() = %#v", got)
	}
}
