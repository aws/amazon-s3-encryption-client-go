// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	GcmTagSizeBits = "128"
	// KMSKeyring is a constant used during decryption to build a KMS key handler.
	KMSKeyring = "kms"
	// KMSContextKeyring is a constant used during decryption to build a kms+context keyring
	KMSContextKeyring = "kms+context"

	kmsDefaultEncryptionContextKey = "AESGCMNoPadding"
	kmsAWSCEKContextKey            = "aws:x-amz-cek-alg"
	kmsMismatchCEKAlg              = "the content encryption algorithm used at encryption time does not match the algorithm stored for decryption time. The object may be altered or corrupted"
	kmsReservedKeyConflictErrMsg   = "conflict in reserved KMS Encryption Context key %s. This value is reserved for the S3 Encryption client and cannot be set by the user"
)

// KmsAPIClient is a client that implements the GenerateDataKey and Decrypt operations
type KmsAPIClient interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KeyringOptions is for additional configuration on Keyring types to perform additional behaviors.
// When EnableLegacyWrappingAlgorithms is set to true, the Keyring MAY decrypt objects encrypted
// using legacy wrapping algorithms such as KMS v1.
type KeyringOptions struct {
	EnableLegacyWrappingAlgorithms bool
}

// KmsKeyring encrypts with encryption context and on decrypt it checks for the algorithm
// in the material description and makes the call to commonDecrypt with the correct parameters
type KmsKeyring struct {
	kmsClient                KmsAPIClient
	KmsKeyId                 string
	legacyWrappingAlgorithms bool
}

// KmsAnyKeyKeyring is decrypt-only.
type KmsAnyKeyKeyring struct {
	kmsClient                KmsAPIClient
	legacyWrappingAlgorithms bool
}

// NewKmsKeyring creates a new KmsKeyring which calls KMS to encrypt/decrypt the data key used to encrypt the S3
// object. The KmsKeyring will always use the kmsKeyId provided to encrypt and decrypt messages.
func NewKmsKeyring(apiClient KmsAPIClient, kmsKeyId string, optFns ...func(options *KeyringOptions)) *KmsKeyring {
	options := KeyringOptions{
		EnableLegacyWrappingAlgorithms: false,
	}
	for _, fn := range optFns {
		fn(&options)
	}

	return &KmsKeyring{
		kmsClient:                apiClient,
		KmsKeyId:                 kmsKeyId,
		legacyWrappingAlgorithms: options.EnableLegacyWrappingAlgorithms,
	}
}

// NewKmsDecryptOnlyAnyKeyKeyring creates a new KmsAnyKeyKeyring. This Keyring uses the KMS identifier
// persisted in the data key's ciphertext to decrypt the data key.
func NewKmsDecryptOnlyAnyKeyKeyring(apiClient KmsAPIClient, optFns ...func(options *KeyringOptions)) *KmsAnyKeyKeyring {
	options := KeyringOptions{
		EnableLegacyWrappingAlgorithms: false,
	}
	for _, fn := range optFns {
		fn(&options)
	}

	return &KmsAnyKeyKeyring{
		kmsClient:                apiClient,
		legacyWrappingAlgorithms: options.EnableLegacyWrappingAlgorithms,
	}
}

// OnEncrypt generates/encrypts a data key for use with content encryption.
func (k *KmsKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	var matDesc MaterialDescription = materials.encryptionContext
	if _, ok := matDesc[kmsAWSCEKContextKey]; ok {
		return nil, fmt.Errorf(kmsReservedKeyConflictErrMsg, kmsAWSCEKContextKey)
	}
	if matDesc == nil {
		matDesc = map[string]string{}
	}

	requestMatDesc := matDesc.Clone()
	requestMatDesc[kmsAWSCEKContextKey] = kmsDefaultEncryptionContextKey

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
		TagLength:           GcmTagSizeBits,
		MaterialDescription: requestMatDesc,
		EncryptedKey:        out.CiphertextBlob,
	}

	return cryptoMaterials, nil
}

// OnDecrypt decrypts the encryptedDataKeys and returns them in materials
// for use with content decryption, or an error if the object cannot be decrypted
// by the Keyring as its configured.
func (k *KmsKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm == KMSKeyring && !k.legacyWrappingAlgorithms {
		return nil, fmt.Errorf("to decrypt x-amz-cek-alg value `%s` you must enable legacyWrappingAlgorithms on the keyring", materials.DataKey.DataKeyAlgorithm)
	}

	if materials.DataKey.DataKeyAlgorithm == KMSKeyring && k.legacyWrappingAlgorithms {
		return commonDecrypt(ctx, materials, encryptedDataKey, &k.KmsKeyId, nil, k.kmsClient)
	} else if materials.DataKey.DataKeyAlgorithm == KMSContextKeyring && !k.legacyWrappingAlgorithms {
		return commonDecrypt(ctx, materials, encryptedDataKey, &k.KmsKeyId, materials.MaterialDescription, k.kmsClient)
	} else {
		return nil, fmt.Errorf("x-amz-cek-alg value `%s` did not match an expected algorithm", materials.DataKey.DataKeyAlgorithm)
	}
}

func (k *KmsKeyring) isAWSFixture() bool {
	return true
}

// OnEncrypt generates/encrypts a data key for use with content encryption
// The KmsAnyKeyKeyring does not support OnEncrypt, so an error is returned.
func (k *KmsAnyKeyKeyring) OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*CryptographicMaterials, error) {
	return nil, fmt.Errorf("KmsAnyKeyKeyring MUST NOT be used to encrypt new data")
}

// OnDecrypt decrypts the encryptedDataKeys and returns them in materials
// for use with content decryption, or an error if the object cannot be decrypted
// by the Keyring as its configured.
func (k *KmsAnyKeyKeyring) OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*CryptographicMaterials, error) {
	if materials.DataKey.DataKeyAlgorithm == KMSKeyring && k.legacyWrappingAlgorithms {
		return commonDecrypt(ctx, materials, encryptedDataKey, nil, nil, k.kmsClient)
	} else if materials.DataKey.DataKeyAlgorithm == KMSContextKeyring && !k.legacyWrappingAlgorithms {
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
		KeyId:             kmsKeyId,
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
	}
	return cryptoMaterials, nil
}
