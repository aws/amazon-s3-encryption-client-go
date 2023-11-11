package client

import (
	"bytes"
	"context"
	"github.com/aws/amazon-s3-encryption-client-go/internal"
	"io"
	"io/ioutil"
)

type mockCMM struct{}

func (m mockCMM) GetEncryptionMaterials(ctx context.Context, matDesc internal.MaterialDescription) (*internal.CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &internal.CryptographicMaterials{
		Key:          nil,
		IV:           nil,
		CEKAlgorithm: internal.AESGCMNoPadding,
	}, nil
}

func (m mockCMM) DecryptMaterials(ctx context.Context, objectMetadata internal.ObjectMetadata) (*internal.CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &internal.CryptographicMaterials{
		Key:                 nil,
		IV:                  nil,
		KeyringAlgorithm:    "",
		CEKAlgorithm:        "",
		TagLength:           "",
		MaterialDescription: nil,
		EncryptedKey:        nil,
		Padder:              nil,
	}, nil
}

type mockKeyring struct{}

// OnEncrypt generates/encrypts a data key for use with content encryption
func (m mockKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*internal.CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &internal.CryptographicMaterials{
		Key:                 nil,
		IV:                  nil,
		KeyringAlgorithm:    "",
		CEKAlgorithm:        "",
		TagLength:           "",
		MaterialDescription: nil,
		EncryptedKey:        nil,
		Padder:              nil,
	}, nil
}

// OnDecrypt decrypts the encryptedDataKeys and returns them in materials
// for use with content decryption
func (m mockKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*internal.CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &internal.CryptographicMaterials{
		Key:                 nil,
		IV:                  nil,
		KeyringAlgorithm:    "",
		CEKAlgorithm:        "",
		TagLength:           "",
		MaterialDescription: nil,
		EncryptedKey:        nil,
		Padder:              nil,
	}, nil
}

type mockContentCipher struct {
	materials internal.CryptographicMaterials
}

func (cipher *mockContentCipher) GetCipherData() internal.CryptographicMaterials {
	return cipher.materials
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
