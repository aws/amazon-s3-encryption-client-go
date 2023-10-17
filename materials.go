package s3crypto

import "encoding/base64"

type DecryptionMaterials struct {
	DataKey             DataKey
	ContentIV           []byte //base64 decoded content IV
	MaterialDescription MaterialDescription
	ContentAlgorithm    string
	Padder              Padder
	TagLength           string
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
		TagLength:           md.TagLen,
	}, nil
}

type DataKey struct {
	KeyMaterial      []byte
	EncryptedDataKey []byte
	DataKeyAlgorithm string
}

type EncryptionMaterials struct {
	gcmKeySize   int
	gcmNonceSize int
	algorithm    string
}

func NewEncryptionMaterials() *EncryptionMaterials {
	return &EncryptionMaterials{
		gcmKeySize:   gcmKeySize,
		gcmNonceSize: gcmNonceSize,
		algorithm:    AESGCMNoPadding,
	}
}
