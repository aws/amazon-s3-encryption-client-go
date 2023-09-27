package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KmsDecryptOnlyKeyring is decrypt-only
type KmsDecryptOnlyKeyring struct {
	kmsClient KmsAPIClient
	KmsKeyId  string
	matDesc   MaterialDescription
}

type KmsContextKeyring struct {
	kmsClient KmsAPIClient
	KmsKeyId  string
	matDesc   MaterialDescription
}

// TODO: Write KmsAnyKeyKeyrings

func NewKmsDecryptOnlyKeyring(apiClient KmsAPIClient, cmkId string, matdesc MaterialDescription) *KmsDecryptOnlyKeyring {
	return &KmsDecryptOnlyKeyring{
		kmsClient: apiClient,
		KmsKeyId:  cmkId,
		matDesc:   matdesc}
}

func (k *KmsDecryptOnlyKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	return nil, fmt.Errorf("KmsDecryptOnlyKeyring MUST NOT be used to encrypt new data")
}

// TODO: Refactor to reuse implementation, no context is a single case of any context
func (k *KmsDecryptOnlyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey []byte) (*CryptographicMaterials, error) {
	in := &kms.DecryptInput{
		EncryptionContext: materials.MaterialDescription,
		CiphertextBlob:    encryptedDataKey,
	}

	out, err := k.kmsClient.Decrypt(ctx, in)
	if err != nil {
		return nil, err
	}

	materials.PlaintextDataKey.KeyMaterial = out.Plaintext
	cryptoMaterials := &CryptographicMaterials{
		Key:                 out.Plaintext,
		IV:                  materials.ContentIV,
		KeyringAlgorithm:    "", // todo hardcoded (also who cares lol)
		CEKAlgorithm:        materials.ContentAlgorithm,
		TagLength:           "128", // todo hardcoded
		MaterialDescription: materials.MaterialDescription,
		EncryptedKey:        materials.DataKey,
		Padder:              nil, // todo hardcoded
	}
	return cryptoMaterials, nil
}

func NewKmsContextKeyring(apiClient KmsAPIClient, cmkId string, matdesc MaterialDescription) *KmsContextKeyring {
	return &KmsContextKeyring{
		kmsClient: apiClient,
		KmsKeyId:  cmkId,
		matDesc:   matdesc,
	}
}

func (k *KmsContextKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	out, err := k.kmsClient.GenerateDataKey(ctx,
		&kms.GenerateDataKeyInput{
			EncryptionContext: k.matDesc,
			KeyId:             &k.KmsKeyId,
			KeySpec:           types.DataKeySpecAes256,
		})
	if err != nil {
		return &CryptographicMaterials{}, err
	}
	iv, err := generateBytes(materials.gcmNonceSize)
	if err != nil {
		return &CryptographicMaterials{}, err
	}

	cryptoMaterials := &CryptographicMaterials{
		Key:                 out.Plaintext,
		IV:                  iv,
		KeyringAlgorithm:    KMSContextKeyring,
		CEKAlgorithm:        materials.algorithm,
		TagLength:           "", // TODO: Is this used anywhere?
		MaterialDescription: k.matDesc,
		EncryptedKey:        out.CiphertextBlob,
		Padder:              nil, // TODO: deal with padder stuff
	}

	return cryptoMaterials, nil
}

// TODO: Refactor to reuse implementation, no context is a single case of any context
func (k *KmsContextKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey []byte) (*CryptographicMaterials, error) {
	in := &kms.DecryptInput{
		EncryptionContext: materials.MaterialDescription,
		CiphertextBlob:    encryptedDataKey,
	}

	out, err := k.kmsClient.Decrypt(ctx, in)
	if err != nil {
		return nil, err
	}

	materials.PlaintextDataKey.KeyMaterial = out.Plaintext
	cryptoMaterials := &CryptographicMaterials{
		Key:                 out.Plaintext,
		IV:                  materials.ContentIV,
		KeyringAlgorithm:    "", // todo hardcoded (also who cares lol)
		CEKAlgorithm:        materials.ContentAlgorithm,
		TagLength:           "128", // todo hardcoded
		MaterialDescription: materials.MaterialDescription,
		EncryptedKey:        materials.DataKey,
		Padder:              nil, // todo hardcoded
	}
	return cryptoMaterials, nil
}
