package hostpidptrace

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestWorkerProtocolRoundTripKeepsCommandInsideFrame(t *testing.T) {
	secret := "printf secret-marker"
	request := workerRequest{
		Target: Candidate{PID: 42, StartTime: 99}, Command: secret,
		TimeoutNS: int64(time.Second), OutputLimit: 100,
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, request); err != nil {
		t.Fatal(err)
	}
	var decoded workerRequest
	if err := readFrame(&frame, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Command != secret || decoded.Target.PID != 42 {
		t.Fatalf("decoded request = %#v", decoded)
	}
	if strings.Contains(WorkerArgument, secret) {
		t.Fatal("worker selector disclosed command")
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
	if err := writeFrame(&framed, workerRequest{Target: Candidate{PID: 2}, Command: "id", TimeoutNS: 1, OutputLimit: 1}); err != nil {
		t.Fatal(err)
	}
	framed.WriteByte('x')
	if err := readFrame(&framed, &workerRequest{}); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing frame error = %v", err)
	}
}

func TestWorkerProtocolRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, payload := range []string{
		`{"target":{"pid":2},"command":"id","timeout_ns":1,"output_limit":1,"unexpected":true}`,
		`{"target":{"pid":2},"command":"id","command":"whoami","timeout_ns":1,"output_limit":1}`,
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
