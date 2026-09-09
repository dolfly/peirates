package hostpidptrace

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

type workerRequest struct {
	Target      Candidate `json:"target"`
	Command     string    `json:"command"`
	TimeoutNS   int64     `json:"timeout_ns"`
	OutputLimit int64     `json:"output_limit"`
}

type workerResponse struct {
	Result Result `json:"result"`
	Error  string `json:"error,omitempty"`
}

func requestFromOptions(options RunOptions) workerRequest {
	return workerRequest{
		Target: options.Target, Command: options.Command,
		TimeoutNS: int64(options.Timeout), OutputLimit: options.OutputLimit,
	}
}

func (request workerRequest) options() (RunOptions, error) {
	return normalizeRunOptions(RunOptions{
		Target: request.Target, Command: request.Command,
		Timeout: time.Duration(request.TimeoutNS), OutputLimit: request.OutputLimit,
	})
}

func writeFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode worker protocol: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxProtocolBytes {
		return fmt.Errorf("worker protocol payload size %d is invalid", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := io.Copy(writer, bytes.NewReader(header[:])); err != nil {
		return fmt.Errorf("write worker protocol header: %w", err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("write worker protocol payload: %w", err)
	}
	return nil
}

func readFrame(reader io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("read worker protocol header: %w", err)
	}
	size := int(binary.BigEndian.Uint32(header[:]))
	if size <= 0 || size > maxProtocolBytes {
		return fmt.Errorf("worker protocol payload size %d is invalid", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return fmt.Errorf("read worker protocol payload: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode worker protocol: %w", err)
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return fmt.Errorf("decode worker protocol: %w", err)
	}
	if decoder.More() {
		return errors.New("worker protocol has duplicate or trailing data")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("worker protocol has duplicate or trailing data")
	}
	var trailing [1]byte
	if count, err := reader.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
		return errors.New("worker protocol has trailing framed data")
	}
	return nil
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate field %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return walk()
}
