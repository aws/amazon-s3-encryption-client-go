package s3crypto

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
)

type mockGeneratorV2 struct{}

func (m mockGeneratorV2) GenerateCipherDataWithCEKAlg(ctx context.Context, keySize int, ivSize int, cekAlg string) (CipherData, error) {
	cd := CipherData{
		Key: make([]byte, keySize),
		IV:  make([]byte, ivSize),
	}
	return cd, nil
}

func (m mockGeneratorV2) DecryptKey(key []byte) ([]byte, error) {
	return make([]byte, 16), nil
}

type mockCipherBuilderV2 struct {
	generator CipherDataGeneratorWithCEKAlg
}

func (builder mockCipherBuilderV2) ContentCipher() (ContentCipher, error) {
	cd, err := builder.generator.GenerateCipherDataWithCEKAlg(context.Background(), 32, 16, "mock-cek-alg")
	if err != nil {
		return nil, err
	}
	return &mockContentCipher{cd}, nil
}

type mockContentCipher struct {
	cd CipherData
}

func (cipher *mockContentCipher) GetCipherData() CipherData {
	return cipher.cd
}

func (cipher *mockContentCipher) EncryptContents(src io.Reader) (io.Reader, error) {
	b, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, err
	}
	size := len(b)
	b = bytes.Repeat([]byte{1}, size)
	return bytes.NewReader(b), nil
}

func (cipher *mockContentCipher) DecryptContents(src io.ReadCloser) (io.ReadCloser, error) {
	b, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, err
	}
	size := len(b)
	return ioutil.NopCloser(bytes.NewReader(make([]byte, size))), nil
}

type mockKMS struct {
	KmsAPIClient
}

type mockPadder struct {
}

func (m mockPadder) Pad(i []byte, i2 int) ([]byte, error) {
	return i, nil
}

func (m mockPadder) Unpad(i []byte) ([]byte, error) {
	return i, nil
}

func (m mockPadder) Name() string {
	return "mockPadder"
}
