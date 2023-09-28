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

// KmsDecryptOnlyAnyKeyKeyring is decrypt-only
type KmsDecryptOnlyAnyKeyKeyring struct {
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

// TODO: Refactor to reuse implementation, no context is a single case of any context
func (k *KmsDecryptOnlyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey []byte) (*CryptographicMaterials, error) {
	in := &kms.DecryptInput{
		// TODO: can the customer put _anything_ here?
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
	if _, ok := k.matDesc[kmsAWSCEKContextKey]; ok {
		return nil, fmt.Errorf(kmsReservedKeyConflictErrMsg, kmsAWSCEKContextKey)
	}
	if k.matDesc == nil {
		k.matDesc = map[string]string{}
	}
	k.matDesc[kmsAWSCEKContextKey] = materials.algorithm

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
		KeyId:             &k.KmsKeyId,
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

func NewKmsDecryptOnlyAnyKeyKeyring(apiClient KmsAPIClient) *KmsDecryptOnlyAnyKeyKeyring {
	return &KmsDecryptOnlyAnyKeyKeyring{
		kmsClient: apiClient,
	}
}

func (k *KmsDecryptOnlyAnyKeyKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	return nil, fmt.Errorf("KmsDecryptOnlyAnyKeyKeyring MUST NOT be used to encrypt new data")
}

// TODO: Refactor to reuse implementation, no context is a single case of any context
func (k *KmsDecryptOnlyAnyKeyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey []byte) (*CryptographicMaterials, error) {
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
