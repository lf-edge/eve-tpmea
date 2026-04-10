// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tpmea

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/canonical/go-tpm2"
)

// ConnectToSwtpm redirects all TPM calls in this library to the software TPM
// listening on the given Unix socket path. Call this before any other library
// function when running against swtpm.
func ConnectToSwtpm(socketPath string) {
	SetTPMHandleFunc(func() (*tpm2.TPMContext, error) {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, fmt.Errorf("cannot connect to swtpm socket %s: %w", socketPath, err)
		}
		return tpm2.NewTPMContext(&swtpmSocketTCTI{conn: conn}), nil
	})
}

// swtpmSocketTCTI implements tpm2.TCTI over a Unix socket connection to swtpm.
// Each TPM response is length-prefixed so we read the 6-byte header first to
// find out how many bytes the full response is.
type swtpmSocketTCTI struct {
	conn net.Conn
	rsp  *bytes.Reader
}

func (t *swtpmSocketTCTI) Read(data []byte) (int, error) {
	if t.rsp == nil {
		hdr := make([]byte, 6)
		if _, err := io.ReadFull(t.conn, hdr); err != nil {
			return 0, err
		}
		responseSize := binary.BigEndian.Uint32(hdr[2:6])
		buf := make([]byte, responseSize)
		copy(buf, hdr)
		if _, err := io.ReadFull(t.conn, buf[6:]); err != nil {
			return 0, err
		}
		t.rsp = bytes.NewReader(buf)
	}
	n, err := t.rsp.Read(data)
	if err == io.EOF {
		t.rsp = nil
	}
	return n, err
}

func (t *swtpmSocketTCTI) Write(data []byte) (int, error) { return t.conn.Write(data) }
func (t *swtpmSocketTCTI) Close() error                   { return t.conn.Close() }
func (t *swtpmSocketTCTI) MakeSticky(_ tpm2.Handle, _ bool) error {
	return errors.New("not implemented")
}
func (t *swtpmSocketTCTI) SetTimeout(timeout time.Duration) error {
	if timeout == tpm2.InfiniteTimeout {
		return t.conn.SetDeadline(time.Time{})
	}
	return t.conn.SetDeadline(time.Now().Add(timeout))
}
