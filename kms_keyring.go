package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	// KMSKeyring is a constant used during decryption to build a KMS key handler.
	KMSKeyring = "kms"
	// KMSContextKeyring is a constant used during decryption to build a kms+context keyring
	KMSContextKeyring = "kms+context"

	kmsAWSCEKContextKey          = "aws:" + cekAlgorithmHeader
	kmsMismatchCEKAlg            = "the content encryption algorithm used at encryption time does not match the algorithm stored for decryption time. The object may be altered or corrupted"
	kmsReservedKeyConflictErrMsg = "conflict in reserved KMS Encryption Context key %s. This value is reserved for the S3 Encryption Client and cannot be set by the user"
)

// KmsAPIClient is a client that implements the GenerateDataKey and Decrypt operations
type KmsAPIClient interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KmsKeyring encrypts with encryption context and on decrypt it checks for the algorithm
// in the material description and makes the call to commonDecrypt with the correct parameters
type KmsKeyring struct {
	kmsClient KmsAPIClient
	KmsKeyId  string
	matDesc   MaterialDescription
}

// KmsAnyKeyKeyring is decrypt-only
type KmsAnyKeyKeyring struct {
	kmsClient KmsAPIClient
	matDesc   MaterialDescription
}

func NewKmsKeyring(apiClient KmsAPIClient, cmkId string, matdesc MaterialDescription) *KmsKeyring {
	return &KmsKeyring{
		kmsClient: apiClient,
		KmsKeyId:  cmkId,
		matDesc:   matdesc,
	}
}

func NewKmsDecryptOnlyAnyKeyKeyring(apiClient KmsAPIClient) *KmsAnyKeyKeyring {
	return &KmsAnyKeyKeyring{
		kmsClient: apiClient,
	}
}

func (k *KmsKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
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
		Padder:              nil,
	}

	return cryptoMaterials, nil
}

func (k *KmsKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm == KMSKeyring {
		return commonDecrypt(ctx, materials, encryptedDataKey, &k.KmsKeyId, nil, k.kmsClient)
	} else if materials.DataKey.DataKeyAlgorithm == KMSContextKeyring {
		return commonDecrypt(ctx, materials, encryptedDataKey, &k.KmsKeyId, materials.MaterialDescription, k.kmsClient)
	} else {
		return nil, fmt.Errorf("x-amz-cek-alg value `%s` did not match an expected algorithm", materials.DataKey.DataKeyAlgorithm)
	}
}

func (k *KmsKeyring) isAWSFixture() bool {
	return true
}

func (k *KmsAnyKeyKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	return nil, fmt.Errorf("KmsAnyKeyKeyring MUST NOT be used to encrypt new data")
}

func (k *KmsAnyKeyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm == KMSKeyring {
		return commonDecrypt(ctx, materials, encryptedDataKey, nil, nil, k.kmsClient)
	} else if materials.DataKey.DataKeyAlgorithm == KMSContextKeyring {
		return commonDecrypt(ctx, materials, encryptedDataKey, nil, materials.MaterialDescription, k.kmsClient)
	} else {
		return nil, fmt.Errorf("x-amz-cek-alg value `%s` did not match an expected algorithm", materials.DataKey.DataKeyAlgorithm)
	}
}

func (k *KmsAnyKeyKeyring) isAWSFixture() bool {
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

	materials.DataKey.KeyMaterial = out.Plaintext
	cryptoMaterials := &CryptographicMaterials{
		Key:                 out.Plaintext,
		IV:                  materials.ContentIV,
		KeyringAlgorithm:    materials.DataKey.DataKeyAlgorithm,
		CEKAlgorithm:        materials.ContentAlgorithm,
		TagLength:           materials.TagLength,
		MaterialDescription: materials.MaterialDescription,
		EncryptedKey:        materials.DataKey.EncryptedDataKey,
		Padder:              materials.Padder,
	}
	return cryptoMaterials, nil
}
