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
	DataKey             DataKey
	ContentIV           []byte //base64 decoded content IV
	MaterialDescription MaterialDescription
	ContentAlgorithm    string
	Padder              Padder
}

func NewDecryptionMaterials(md ObjectMetadata, padderMap map[string]Padder) (*DecryptionMaterials, error) {
	// TODO: Move decoding into ObjectMetadata
	key, err := base64.StdEncoding.DecodeString(md.CipherKey)
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(md.IV)
	if err != nil {
		return nil, err
	}
	materialDescription := MaterialDescription{}
	err = materialDescription.decodeDescription([]byte(md.MatDesc))

	dataKey := DataKey{
		KeyMaterial:      nil,
		EncryptedDataKey: key,
		DataKeyAlgorithm: md.KeyringAlg,
	}

	var padder Padder
	if padderMap[md.KeyringAlg] != nil {
		// prefer custom padder, if registered
		padder = padderMap[md.CEKAlg]
	} else if md.CEKAlg == "AES/CBC/PKCS5Padding" {
		// else use default CBC padding
		padder = aescbcPadding
	}

	if err != nil {
		return nil, err
	}
	return &DecryptionMaterials{
		DataKey:             dataKey,
		ContentIV:           iv,
		MaterialDescription: materialDescription,
		ContentAlgorithm:    md.CEKAlg,
		Padder:              padder,
	}, nil
}

type DataKey struct {
	KeyMaterial      []byte
	EncryptedDataKey []byte
	DataKeyAlgorithm string
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
	OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error)
}
