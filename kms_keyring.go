package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	// KMSContextKeyring is a constant used during decryption to build a kms+context key handler
	KMSContextKeyring = "kms+context"
	// KMSKeyring is a constant used during decryption to build a KMS key handler.
	KMSKeyring = "kms"

	kmsAWSCEKContextKey          = "aws:" + cekAlgorithmHeader
	kmsMismatchCEKAlg            = "the content encryption algorithm used at encryption time does not match the algorithm stored for decryption time. The object may be altered or corrupted"
	kmsReservedKeyConflictErrMsg = "conflict in reserved KMS Encryption Context key %s. This value is reserved for the S3 Encryption Client and cannot be set by the user"
)

// KmsAPIClient is a client that implements the GenerateDataKey and Decrypt operations
type KmsAPIClient interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

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

// KmsAnyKeyKeyring is decrypt-only
type KmsAnyKeyKeyring struct {
	kmsClient KmsAPIClient
	matDesc   MaterialDescription
}

// KmsContextAnyKeyKeyring is decrypt-only
type KmsContextAnyKeyKeyring struct {
	kmsClient KmsAPIClient
	matDesc   MaterialDescription
}

func NewKmsDecryptOnlyKeyring(apiClient KmsAPIClient, cmkId string, matdesc MaterialDescription) *KmsDecryptOnlyKeyring {
	return &KmsDecryptOnlyKeyring{
		kmsClient: apiClient,
		KmsKeyId:  cmkId,
		matDesc:   matdesc}
}

func (k *KmsDecryptOnlyKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	return nil, fmt.Errorf("KmsDecryptOnlyKeyring MUST NOT be used to encrypt new data")
}

func (k *KmsDecryptOnlyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm != KMSKeyring {
		return nil, fmt.Errorf("x-amz-cek-alg value `%s` did not match the expected algorithm `%s` for this keyring", materials.DataKey.DataKeyAlgorithm, KMSKeyring)
	}
	return commonDecrypt(ctx, materials, encryptedDataKey, &k.KmsKeyId, nil, k.kmsClient)
}

func (k *KmsDecryptOnlyKeyring) isAWSFixture() bool {
	return true
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
		TagLength:           "", // TODO: Is this used anywhere?
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

func NewKmsDecryptOnlyAnyKeyKeyring(apiClient KmsAPIClient) *KmsAnyKeyKeyring {
	return &KmsAnyKeyKeyring{
		kmsClient: apiClient,
	}
}

func (k *KmsAnyKeyKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	return nil, fmt.Errorf("KmsAnyKeyKeyring MUST NOT be used to encrypt new data")
}

func (k *KmsAnyKeyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm != KMSKeyring {
		return nil, fmt.Errorf("x-amz-cek-alg value `%s` did not match the expected algorithm `%s` for this keyring", materials.DataKey.DataKeyAlgorithm, KMSKeyring)
	}
	return commonDecrypt(ctx, materials, encryptedDataKey, nil, nil, k.kmsClient)
}

func (k *KmsAnyKeyKeyring) isAWSFixture() bool {
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

func commonDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey, kmsKeyId *string, matDesc MaterialDescription, kmsClient KmsAPIClient) (*CryptographicMaterials, error) {
	if matDesc != nil {
		if v, ok := matDesc[kmsAWSCEKContextKey]; !ok {
			return nil, fmt.Errorf("required key %v is missing from encryption context", kmsAWSCEKContextKey)
		} else if v != materials.ContentAlgorithm {
			return nil, fmt.Errorf(kmsMismatchCEKAlg)
		}
	}

	in := &kms.DecryptInput{
		EncryptionContext: materials.MaterialDescription,
		CiphertextBlob:    encryptedDataKey.EncryptedDataKey,
		KeyId:             kmsKeyId, // TODO possible nil pointer?
	}

	out, err := kmsClient.Decrypt(ctx, in)
	if err != nil {
		return nil, err
	}

	// TODO: This should probably be determined earlier
	// TODO: Also SHOULD be able to be customized at CMM level
	var padder Padder
	if materials.ContentAlgorithm == "AES/CBC/PKCS5Padding" {
		padder = aescbcPadding
	}

	materials.DataKey.KeyMaterial = out.Plaintext
	cryptoMaterials := &CryptographicMaterials{
		Key:                 out.Plaintext,
		IV:                  materials.ContentIV,
		KeyringAlgorithm:    materials.DataKey.DataKeyAlgorithm,
		CEKAlgorithm:        materials.ContentAlgorithm,
		TagLength:           "128", // todo hardcoded
		MaterialDescription: materials.MaterialDescription,
		EncryptedKey:        materials.DataKey.EncryptedDataKey,
		Padder:              padder,
	}
	return cryptoMaterials, nil
}
