package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inguardians/peirates/internal/modules/hostproc"
)

var probeHostProcCorePattern = hostproc.Probe
var runHostProcCorePatternBreakout = hostproc.Launch

var launchHostProcCorePatternBreakout = func() error {
	return launchHostProcCorePatternBreakoutWithStreams(os.Stdin, os.Stdout, os.Stderr)
}

func launchHostProcCorePatternBreakoutWithStreams(stdin io.Reader, stdout, stderr io.Writer) error {
	reader := bufio.NewReader(stdin)
	hostProcPath, err := readEscapePromptLine(reader, stdout, "Host procfs mount [auto-detect]: ")
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read host procfs mount: %w", err)
	}

	finding, err := probeHostProcCorePattern(context.Background(), hostproc.Options{HostProcPath: hostProcPath})
	if err != nil {
		return fmt.Errorf("probe host procfs: %w", err)
	}
	fmt.Fprintf(stdout, "Qualified host procfs: %s\n", finding.HostProcPath)
	fmt.Fprintf(stdout, "Current host core_pattern: %q\n", finding.OriginalCorePattern)
	if finding.Caveat != "" {
		fmt.Fprintln(stdout, finding.Caveat)
	}

	confirmationToken := hostproc.ConfirmationToken
	allowReplacePipedHandler := false
	if strings.HasPrefix(strings.TrimSpace(finding.OriginalCorePattern), "|") {
		allowReplacePipedHandler = true
		confirmationToken = hostproc.PipedHandlerOverrideToken
		fmt.Fprintln(stderr, "WARNING: the host already has a piped crash handler. Replacing it may disrupt crash processing for every process sharing this kernel.")
	} else {
		fmt.Fprintln(stderr, "WARNING: this temporarily changes the kernel-wide core_pattern and intentionally crashes one disposable Peirates child.")
	}
	confirmation, err := readEscapePromptLine(reader, stdout, fmt.Sprintf("Type %s to continue: ", confirmationToken))
	if errors.Is(err, io.EOF) {
		return errors.New("breakout cancelled; host core_pattern was not changed")
	}
	if err != nil {
		return fmt.Errorf("read core_pattern confirmation: %w", err)
	}
	if confirmation != confirmationToken {
		return errors.New("breakout cancelled; host core_pattern was not changed")
	}

	expectedCorePattern := finding.OriginalCorePattern
	return runHostProcCorePatternBreakout(context.Background(), hostproc.Options{
		HostProcPath:             finding.HostProcPath,
		ExpectedCorePattern:      &expectedCorePattern,
		AllowReplacePipedHandler: allowReplacePipedHandler,
		ConfirmMutation:          true,
		Stdin:                    remainingEscapeInput(reader, stdin),
		Stdout:                   stdout,
		Stderr:                   stderr,
	})
}
