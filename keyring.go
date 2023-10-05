package s3crypto

import (
	"context"
	"encoding/base64"
)

//	type EncryptionMaterials struct {
//		EncryptedDataKey DataKey
//		IV               []byte
//		KeyringAlgorithm string
//		CEKAlgorithm     string
//		TagLength        string
//	}
//
//	func NewEncryptionMaterials(metadata ObjectMetadata) (*EncryptionMaterials, error) {
//		return &EncryptionMaterials{
//			EncryptedDataKey: DataKey{KeyMaterial: metadata.CipherKey},
//			IV:               nil,
//			KeyringAlgorithm: "",
//			CEKAlgorithm:     "",
//			TagLength:        "",
//		}
//	}
type DecryptionMaterials struct {
	DataKey             []byte //base64 decoded ciphertext data key
	ContentIV           []byte //base64 decoded content IV
	PlaintextDataKey    DataKey
	MaterialDescription MaterialDescription
	ContentAlgorithm    string // TODO: maybe make this an enum? if those exist in Go..
}

func NewDecryptionMaterials(encodedDataKey string, encodedContentIV string, encodedMatDesc string, cekAlg string) (*DecryptionMaterials, error) {
	// TODO: Move decoding into ObjectMetadata
	key, err := base64.StdEncoding.DecodeString(encodedDataKey)
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(encodedContentIV)
	if err != nil {
		return nil, err
	}
	materialDescription := MaterialDescription{}
	err = materialDescription.decodeDescription([]byte(encodedMatDesc))

	if err != nil {
		return nil, err
	}
	return &DecryptionMaterials{
		DataKey:             key,
		ContentIV:           iv,
		MaterialDescription: materialDescription,
		ContentAlgorithm:    cekAlg,
	}, nil
}

// TODO: if this is just byte array, what's the point?
// consider making this a bit more useful? maybe algorithm?
// TODO: I regret this, remove it
type DataKey struct {
	KeyMaterial []byte
}

// Keyring implementations are responsible for encrypting/decrypting data keys
// using some kind of key material.
// Keyring implementations MAY support decryption-only (i.e. for legacy algorithms)
// or both encryption (including data key generation) and decryption.
type Keyring interface {
	// OnEncrypt generates/encrypts a data key for use with content encryption
	OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error)
	// OnDecrypt decrypts the encryptedDataKeys and returns them in materials
	// for use with content decryption
	OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey []byte) (*CryptographicMaterials, error)
}
