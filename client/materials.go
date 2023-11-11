package client

import (
	"encoding/base64"
	"github.com/aws/amazon-s3-encryption-client-go/internal"
)

type DecryptionMaterials struct {
	DataKey             DataKey
	ContentIV           []byte //base64 decoded content IV
	MaterialDescription MaterialDescription
	ContentAlgorithm    string
	Padder              internal.Padder
	TagLength           string
}

func NewDecryptionMaterials(md internal.ObjectMetadata) (*DecryptionMaterials, error) {
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
	err = materialDescription.DecodeDescription([]byte(md.MatDesc))

	if err != nil {
		return nil, err
	}

	dataKey := DataKey{
		KeyMaterial:      nil,
		EncryptedDataKey: key,
		DataKeyAlgorithm: md.KeyringAlg,
	}

	var padder internal.Padder

	if md.CEKAlg == "AES/CBC/PKCS5Padding" {
		// use default CBC padding
		padder = internal.AesCbcPadding
	}

	return &DecryptionMaterials{
		DataKey:             dataKey,
		ContentIV:           iv,
		MaterialDescription: materialDescription,
		ContentAlgorithm:    md.CEKAlg,
		Padder:              padder,
		TagLength:           md.TagLen,
	}, nil
}

type DataKey struct {
	KeyMaterial      []byte
	EncryptedDataKey []byte
	DataKeyAlgorithm string
}

type EncryptionMaterials struct {
	gcmKeySize        int
	gcmNonceSize      int
	algorithm         string
	encryptionContext map[string]string
}

func NewEncryptionMaterials() *EncryptionMaterials {
	return &EncryptionMaterials{
		gcmKeySize:        internal.GcmKeySize,
		gcmNonceSize:      internal.GcmNonceSize,
		algorithm:         internal.AESGCMNoPadding,
		encryptionContext: map[string]string{},
	}
}
