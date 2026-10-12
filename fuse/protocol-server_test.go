// Copyright 2026 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import (
	"bytes"
	"encoding/binary"
	"log"
	"testing"
	"unsafe"
)

func TestProtocolServerParse(t *testing.T) {
	in := [][]byte{
		[]byte("A\x00\x00\x00\x16\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.\x04\x00\x00\x00\x00\x00\x00"),
		[]byte("\x00\x00\x00\x00\x00\x00\x00\x00security.selinux\x00"),
	}
	out := [][]byte{make([]byte, 16), make([]byte, 8)}

	var logBuf bytes.Buffer
	t.Cleanup(func() {
		if logBuf.Len() > 0 {
			t.Logf("protocol-server log:\n%s", logBuf.String())
		}
	})
	opts := MountOptions{}
	opts.Debug = true
	opts.Logger = log.New(&logBuf, "", 0)
	ps := NewProtocolServer(NewDefaultRawFileSystem(), &opts)
	n, status := ps.HandleRequest(in, out)
	if status != OK {
		t.Fatalf("HandleRequest: status %v, want OK", status)
	}
	if n < int(sizeOfOutHeader) {
		t.Fatalf("HandleRequest: wrote %d bytes, want at least %d", n, sizeOfOutHeader)
	}
	length := binary.LittleEndian.Uint32(out[0][0:4])
	if int(length) != n {
		t.Errorf("OutHeader.Length = %d, want %d", length, n)
	}
	// DefaultRawFileSystem.GetXAttr returns ENOSYS, so the reply is
	// header-only with a negative status.
	gotStatus := int32(binary.LittleEndian.Uint32(out[0][4:8]))
	if gotStatus != -int32(ENOSYS) {
		t.Errorf("OutHeader.Status = %d, want %d", gotStatus, -int32(ENOSYS))
	}
}

func TestProtocolServerParsesCompleteSetattr(t *testing.T) {
	request := SetAttrIn{}
	request.Length = uint32(unsafe.Sizeof(request))
	request.Opcode = _OP_SETATTR
	request.NodeId = FUSE_ROOT_ID
	request.Unique = 71
	request.Valid = FATTR_MODE | FATTR_SIZE
	request.Mode = S_IFREG | 0600
	request.Size = 4096
	var input bytes.Buffer
	if err := binary.Write(&input, binary.LittleEndian, request); err != nil {
		t.Fatal(err)
	}
	filesystem := &setattrProtocolFS{RawFileSystem: NewDefaultRawFileSystem()}
	server := NewProtocolServer(filesystem, &MountOptions{})
	output := make([]byte, 4096)
	n, status := server.HandleRequest([][]byte{input.Bytes()}, [][]byte{output})
	if status != OK {
		t.Fatalf("HandleRequest status = %v", status)
	}
	if !filesystem.called || filesystem.input.Valid != request.Valid || filesystem.input.Mode != request.Mode || filesystem.input.Size != request.Size {
		t.Fatalf("SetAttr received %+v, called=%v; want %+v", filesystem.input, filesystem.called, request)
	}
	if n != int(sizeOfOutHeader) || int32(binary.LittleEndian.Uint32(output[4:8])) != -int32(EACCES) {
		t.Fatalf("SetAttr reply = %x; want EACCES", output[:n])
	}
}

type setattrProtocolFS struct {
	RawFileSystem
	called bool
	input  SetAttrIn
}

func (fs *setattrProtocolFS) SetAttr(_ <-chan struct{}, input *SetAttrIn, _ *AttrOut) Status {
	fs.called = true
	fs.input = *input
	return EACCES
}
