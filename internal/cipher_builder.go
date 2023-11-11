package internal

import (
	"context"
	"io"
)

// ContentCipherBuilder is a builder interface that builds
// ciphers for each request.
type ContentCipherBuilder interface {
	ContentCipher() (ContentCipher, error)
}

// ContentCipherBuilderWithContext is a builder interface that builds
// ciphers for each request.
type ContentCipherBuilderWithContext interface {
	ContentCipherWithContext(context.Context) (ContentCipher, error)
}

// ContentCipher deals with encrypting and decrypting content
type ContentCipher interface {
	EncryptContents(io.Reader) (io.Reader, error)
	DecryptContents(io.ReadCloser) (io.ReadCloser, error)
	GetCipherData() CryptographicMaterials
}

// CEKEntry is a builder that returns a proper content decrypter and error
type CEKEntry func(CryptographicMaterials) (ContentCipher, error)

// CryptographicMaterials is used for content encryption. It is used for storing the
// metadata of the encrypted content.
type CryptographicMaterials struct {
	Key                 []byte
	IV                  []byte
	KeyringAlgorithm    string
	CEKAlgorithm        string
	TagLength           string
	MaterialDescription MaterialDescription
	// EncryptedKey should be populated when calling GenerateCipherData
	EncryptedKey []byte
	Padder       Padder
}

// Clone returns a new copy of CryptographicMaterials
func (cm CryptographicMaterials) Clone() (v CryptographicMaterials) {
	v = cm
	v.MaterialDescription = cm.MaterialDescription.Clone()
	return v
}
