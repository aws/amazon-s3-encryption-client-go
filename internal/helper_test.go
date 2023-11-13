package internal

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestBytesReadWriteSeeker_Read(t *testing.T) {
	b := &bytesReadWriteSeeker{[]byte{1, 2, 3}, 0}
	expected := []byte{1, 2, 3}
	buf := make([]byte, 3)
	n, err := b.Read(buf)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if e, a := 3, n; e != a {
		t.Errorf("expected %d, but received %d", e, a)
	}

	if !bytes.Equal(expected, buf) {
		t.Error("expected equivalent byte slices, but received otherwise")
	}
}

func TestBytesReadWriteSeeker_Write(t *testing.T) {
	b := &bytesReadWriteSeeker{}
	expected := []byte{1, 2, 3}
	buf := make([]byte, 3)
	n, err := b.Write([]byte{1, 2, 3})

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if e, a := 3, n; e != a {
		t.Errorf("expected %d, but received %d", e, a)
	}

	n, err = b.Read(buf)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if e, a := 3, n; e != a {
		t.Errorf("expected %d, but received %d", e, a)
	}

	if !bytes.Equal(expected, buf) {
		t.Error("expected equivalent byte slices, but received otherwise")
	}
}

func TestBytesReadWriteSeeker_Seek(t *testing.T) {
	b := &bytesReadWriteSeeker{[]byte{1, 2, 3}, 0}
	expected := []byte{2, 3}
	m, err := b.Seek(1, io.SeekStart)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if e, a := 1, int(m); e != a {
		t.Errorf("expected %d, but received %d", e, a)
	}

	buf := make([]byte, 3)
	n, err := b.Read(buf)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if e, a := 2, n; e != a {
		t.Errorf("expected %d, but received %d", e, a)
	}

	if !bytes.Equal(expected, buf[:n]) {
		t.Error("expected equivalent byte slices, but received otherwise")
	}
}

func TestGetWriterStore_TempFile(t *testing.T) {
	ws, err := GetWriterStore("", true)
	if err != nil {
		t.Fatalf("expected no error, but received %v", err)
	}
	tempFile, ok := ws.ReadWriteSeeker.(*os.File)
	if !ok {
		t.Fatal("io.ReadWriteSeeker expected to be *os.file")
	}

	ws.Cleanup()
	if _, err := os.Stat(tempFile.Name()); !os.IsNotExist(err) {
		t.Errorf("expected temp file be deleted, but still exists %v", tempFile.Name())
	}
}

func TestGetWriterStore_Memory(t *testing.T) {
	ws, err := GetWriterStore("", false)
	if err != nil {
		t.Fatalf("expected no error, but received %v", err)
	}
	if _, ok := ws.ReadWriteSeeker.(*bytesReadWriteSeeker); !ok {
		t.Fatal("io.ReadWriteSeeker expected to be *bytesReadWriteSeeker")
	}
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	ws.Cleanup()
}
