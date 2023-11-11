package internal

import (
	"errors"
	"io"
	"os"
)

type writerStore struct {
	io.ReadWriteSeeker
	Cleanup func()
}

func GetWriterStore(path string, useTempFile bool) (*writerStore, error) {
	if !useTempFile {
		return &writerStore{
			ReadWriteSeeker: &bytesReadWriteSeeker{},
			Cleanup:         func() {},
		}, nil
	}
	// Create temp file to be used later for calculating the SHA256 header
	f, err := os.CreateTemp(path, "")
	if err != nil {
		return nil, err
	}

	ws := &writerStore{
		ReadWriteSeeker: f,
		Cleanup: func() {
			// Close the temp file and Cleanup
			f.Close()
			os.Remove(f.Name())
		},
	}

	return ws, nil
}

type bytesReadWriteSeeker struct {
	buf []byte
	i   int64
}

// Copied from Go stdlib bytes.Reader
func (ws *bytesReadWriteSeeker) Read(b []byte) (int, error) {
	if ws.i >= int64(len(ws.buf)) {
		return 0, io.EOF
	}
	n := copy(b, ws.buf[ws.i:])
	ws.i += int64(n)
	return n, nil
}

func (ws *bytesReadWriteSeeker) Write(b []byte) (int, error) {
	ws.buf = append(ws.buf, b...)
	return len(b), nil
}

// Copied from Go stdlib bytes.Reader
func (ws *bytesReadWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case 0:
		abs = offset
	case 1:
		abs = int64(ws.i) + offset
	case 2:
		abs = int64(len(ws.buf)) + offset
	default:
		return 0, errors.New("bytes.Reader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("bytes.Reader.Seek: negative position")
	}
	ws.i = abs
	return abs, nil
}
