package hostpidptrace

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestWorkerProtocolRoundTripKeepsTerminalIdentityInsideFrame(t *testing.T) {
	request := workerRequest{
		Target:   Candidate{PID: 42, StartTime: 99},
		Terminal: terminalSpec{Number: 7, Identity: Identity{Device: 8, Inode: 9}, DeviceID: 10},
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, request); err != nil {
		t.Fatal(err)
	}
	var decoded workerRequest
	if err := readFrame(&frame, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Terminal != request.Terminal || decoded.Target.PID != 42 {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestWorkerProtocolRejectsMalformedSizeAndTrailingData(t *testing.T) {
	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(maxProtocolBytes+1))
	oversized.Write(header[:])
	if err := readFrame(&oversized, &workerRequest{}); err == nil {
		t.Fatal("oversized frame was accepted")
	}

	var framed bytes.Buffer
	if err := writeFrame(&framed, workerRequest{Target: Candidate{PID: 2}, Terminal: terminalSpec{Number: 1}}); err != nil {
		t.Fatal(err)
	}
	framed.WriteByte('x')
	if err := readFrame(&framed, &workerRequest{}); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing frame error = %v", err)
	}
}

func TestWorkerProtocolRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, payload := range []string{
		`{"target":{"pid":2},"terminal":{"number":1},"unexpected":true}`,
		`{"target":{"pid":2},"target":{"pid":3},"terminal":{"number":1}}`,
	} {
		var frame bytes.Buffer
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
		frame.Write(header[:])
		frame.WriteString(payload)
		if err := readFrame(&frame, &workerRequest{}); err == nil {
			t.Fatalf("malformed payload was accepted: %s", payload)
		}
	}
}
