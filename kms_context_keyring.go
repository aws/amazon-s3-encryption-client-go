package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	// KMSContextKeyring is a constant used during decryption to build a kms+context keyring
	KMSContextKeyring            = "kms+context"
	kmsReservedKeyConflictErrMsg = "conflict in reserved KMS Encryption Context key %s. This value is reserved for the S3 Encryption Client and cannot be set by the user"
)

type KmsContextKeyring struct {
	kmsClient KmsAPIClient
	KmsKeyId  string
	matDesc   MaterialDescription
}

// KmsContextAnyKeyKeyring is decrypt-only
type KmsContextAnyKeyKeyring struct {
	kmsClient KmsAPIClient
	matDesc   MaterialDescription
}

func NewKmsContextKeyring(apiClient KmsAPIClient, cmkId string, matdesc MaterialDescription) *KmsContextKeyring {
	return &KmsContextKeyring{
		kmsClient: apiClient,
		KmsKeyId:  cmkId,
		matDesc:   matdesc,
	}
}

func (k *KmsContextKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	// TODO: matDesc MUST be set per-request, not per-Keyring instance
	if _, ok := k.matDesc[kmsAWSCEKContextKey]; ok {
		return nil, fmt.Errorf(kmsReservedKeyConflictErrMsg, kmsAWSCEKContextKey)
	}
	if k.matDesc == nil {
		k.matDesc = map[string]string{}
	}

	requestMatDesc := k.matDesc.Clone()
	requestMatDesc[kmsAWSCEKContextKey] = AESGCMNoPadding

	out, err := k.kmsClient.GenerateDataKey(ctx,
		&kms.GenerateDataKeyInput{
			EncryptionContext: requestMatDesc,
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
		TagLength:           gcmTagSizeBits,
		MaterialDescription: requestMatDesc,
		EncryptedKey:        out.CiphertextBlob,
		Padder:              nil, // TODO: deal with padder stuff
	}

	return cryptoMaterials, nil
}

func (k *KmsContextKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm != KMSContextKeyring {
		return nil, fmt.Errorf("x-amz-cek-alg value `%s` did not match the expected algorithm `%s` for this keyring", materials.DataKey.DataKeyAlgorithm, KMSContextKeyring)
	}
	return commonDecrypt(ctx, materials, encryptedDataKey, &k.KmsKeyId, materials.MaterialDescription, k.kmsClient)
}

func (k *KmsContextKeyring) isAWSFixture() bool {
	return true
}

func NewKmsContextAnyKeyKeyring(apiClient KmsAPIClient) *KmsContextAnyKeyKeyring {
	return &KmsContextAnyKeyKeyring{
		kmsClient: apiClient,
	}
}

func (k *KmsContextAnyKeyKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	return nil, fmt.Errorf("KmsContextAnyKeyKeyring MUST NOT be used to encrypt new data")
}

func (k *KmsContextAnyKeyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm != KMSContextKeyring {
		return nil, fmt.Errorf("x-amz-cek-alg value `%s` did not match the expected algorithm `%s` for this keyring", materials.DataKey.DataKeyAlgorithm, KMSContextKeyring)
	}
	return commonDecrypt(ctx, materials, encryptedDataKey, nil, materials.MaterialDescription, k.kmsClient)
}

func (k *KmsContextAnyKeyKeyring) isAWSFixture() bool {
	return true
}
