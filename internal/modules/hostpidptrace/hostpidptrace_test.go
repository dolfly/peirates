package hostpidptrace

import (
	"testing"
)

func TestConfirmationPhraseIsPIDSpecific(t *testing.T) {
	if got := ConfirmationPhrase(1234); got != "TRACE-DISPOSABLE-HOST-PROCESS-1234" {
		t.Fatalf("confirmation phrase = %q", got)
	}
}

func validRunOptions() RunOptions {
	return RunOptions{
		Target: Candidate{PID: 12},
		Terminal: terminalSpec{
			Number: 3, Identity: Identity{Device: 4, Inode: 5}, DeviceID: 6,
		},
	}
}

func TestNormalizeRunOptionsRequiresTargetAndTerminalIdentity(t *testing.T) {
	if _, err := normalizeRunOptions(validRunOptions()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RunOptions){
		func(options *RunOptions) { options.Target.PID = 1 },
		func(options *RunOptions) { options.Terminal.Number = -1 },
		func(options *RunOptions) { options.Terminal.Identity = Identity{} },
		func(options *RunOptions) { options.Terminal.DeviceID = 0 },
	} {
		options := validRunOptions()
		mutate(&options)
		if _, err := normalizeRunOptions(options); err == nil {
			t.Fatalf("invalid options were accepted: %#v", options)
		}
	}
}
