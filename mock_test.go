package s3crypto

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
)

type mockKeyring struct{}

type mockCMM struct{}

// OnEncrypt generates/encrypts a data key for use with content encryption
func (m mockKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &CryptographicMaterials{
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
func (m mockKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &CryptographicMaterials{
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

func (m mockCMM) getEncryptionMaterials(ctx context.Context) (*CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &CryptographicMaterials{
		Key:          nil,
		IV:           nil,
		CEKAlgorithm: AESGCMNoPadding,
	}, nil
}

func (m mockCMM) decryptMaterials(ctx context.Context, objectMetadata ObjectMetadata) (*CryptographicMaterials, error) {
	// TODO: make this mock more useful
	return &CryptographicMaterials{
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

func (m mockCMM) GetKeyring() Keyring {
	return nil
}
func (m mockCMM) AddPadder(name string, entry Padder) error {
	return nil
}
func (m mockCMM) GetPadder(name string) (Padder, bool) {
	return nil, false

}
func (m mockCMM) RemovePadder(name string) (Padder, bool) {
	return nil, false
}

type mockContentCipher struct {
	cd CryptographicMaterials
}

func (cipher *mockContentCipher) GetCipherData() CryptographicMaterials {
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
