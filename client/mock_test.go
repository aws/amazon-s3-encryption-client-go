package client

import (
	"bytes"
	"context"
	"github.com/aws/amazon-s3-encryption-client-go/materials"
	"io"
	"io/ioutil"
)

type mockCMM struct{}

func (m mockCMM) GetEncryptionMaterials(ctx context.Context, matDesc materials.MaterialDescription) (*materials.CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &materials.CryptographicMaterials{
		Key:          nil,
		IV:           nil,
		CEKAlgorithm: "AES/GCM/NoPadding",
	}, nil
}

func (m mockCMM) DecryptMaterials(ctx context.Context, req materials.DecryptMaterialsRequest) (*materials.CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &materials.CryptographicMaterials{
		Key:                 nil,
		IV:                  nil,
		KeyringAlgorithm:    "",
		CEKAlgorithm:        "",
		TagLength:           "",
		MaterialDescription: nil,
		EncryptedKey:        nil,
	}, nil
}

type mockKeyring struct{}

// OnEncrypt generates/encrypts a data key for use with content encryption
func (m mockKeyring) OnEncrypt(ctx context.Context, encryptionMaterials *materials.EncryptionMaterials) (*materials.CryptographicMaterials, error) {
	return &materials.CryptographicMaterials{
		Key:                 nil,
		IV:                  nil,
		KeyringAlgorithm:    "",
		CEKAlgorithm:        "",
		TagLength:           "",
		MaterialDescription: nil,
		EncryptedKey:        nil,
	}, nil
	// TODO: make this mock more useful
	return &materials.CryptographicMaterials{}, nil
}

// OnDecrypt decrypts the encryptedDataKeys and returns them in materials
// for use with content decryption
func (m mockKeyring) OnDecrypt(ctx context.Context, decryptionMaterials *materials.DecryptionMaterials, encryptedDataKey materials.DataKey) (*materials.CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &materials.CryptographicMaterials{
		Key:                 nil,
		IV:                  nil,
		KeyringAlgorithm:    "",
		CEKAlgorithm:        "",
		TagLength:           "",
		MaterialDescription: nil,
		EncryptedKey:        nil,
	}, nil
}

type mockContentCipher struct {
	materials materials.CryptographicMaterials
}

func (cipher *mockContentCipher) GetCipherData() materials.CryptographicMaterials {
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
