package hostpidptrace

import (
	"strings"
	"testing"
	"time"
)

func TestConfirmationPhraseIsPIDSpecific(t *testing.T) {
	if got := ConfirmationPhrase(1234); got != "TRACE-DISPOSABLE-HOST-PROCESS-1234" {
		t.Fatalf("confirmation phrase = %q", got)
	}
}

func TestNormalizeRunOptionsRejectsUnsafeCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{name: "empty"},
		{name: "NUL", command: "id\x00uname"},
		{name: "too long", command: strings.Repeat("x", MaxCommandBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeRunOptions(RunOptions{Target: Candidate{PID: 12}, Command: test.command}); err == nil {
				t.Fatal("unsafe command was accepted")
			}
		})
	}
}

func TestNormalizeRunOptionsAppliesBounds(t *testing.T) {
	options, err := normalizeRunOptions(RunOptions{Target: Candidate{PID: 12}, Command: "id"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Timeout != DefaultTimeout || options.OutputLimit != DefaultOutputLimit {
		t.Fatalf("defaults = %#v", options)
	}
	if _, err := normalizeRunOptions(RunOptions{
		Target: Candidate{PID: 12}, Command: "id", Timeout: 6 * time.Minute,
	}); err == nil {
		t.Fatal("excessive timeout was accepted")
	}
}
