// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v3/algorithms"
)

// NewAESGCMCommittingContentCipher returns a new encryption only AES/GCM mode structure with a specific cipher data generator
// that will provide keys to be used for content encryption.
//
// Note: This uses the Go stdlib AEAD implementation for AES/GCM. Due to this, objects to be encrypted or decrypted
// will be fully loaded into memory before encryption or decryption can occur. Caution must be taken to avoid memory
// allocation failures.
func NewAESGCMCommittingContentCipher(materials materials.CryptographicMaterials) (ContentCipher, error) {
	materials.CEKAlgorithm = algorithms.AESGCMCommitKey
	materials.TagLength = GcmTagSizeBits

	// Persist original IV to store in the object metadata
	original_iv := materials.IV

	var storedKeyCommitment []byte = nil
	if materials.KeyCommitment != nil {
		storedKeyCommitment = make([]byte, len(materials.KeyCommitment))
		copy(storedKeyCommitment, materials.KeyCommitment)
	}

	//= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
	//= type=implication
	//# The client MUST use HKDF to derive the key commitment value and the derived encrypting key as described in [Key Derivation](key-derivation.md).
	keys, err := DeriveKeys(materials.Key, materials.IV, algorithms.AlgAES256GCMHkdfSha512CommitKey.ID(), storedKeyCommitment)
	if err != nil {
		return nil, err
	}

	materials.Key = keys.DerivedEncryptionKey
	//= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
	//# The derived key commitment value MUST be set or returned from the encryption process such that it can be included in the content metadata.
	materials.KeyCommitment = keys.CommitKey

	//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
	//= type=implication
	//# When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
	//# the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
	//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
	//= type=implication
	//# The IV's total length MUST match the IV length defined by the algorithm suite.
	var nonce = [12]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	materials.IV = nonce[:]

	//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
	//= type=implication
	//# The client MUST initialize the cipher, or call an AES-GCM encryption API,
	//# with the derived encryption key,
	//# an IV containing only bytes with the value 0x01,
	//# and the tag length defined in the Algorithm Suite
	//# when encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.
	cipher, err := newAESGCM(materials)
	if err != nil {
		return nil, err
	}

	// Restore original non-zero IV for metadata storage
	materials.IV = original_iv

	return &aesGCMContentCipher{
		CryptographicMaterials: materials,
		Cipher:                 cipher,
	}, nil
}

func NewAESGCMDecryptCommittingContentCipher(materials materials.CryptographicMaterials) (ContentCipher, error) {
	// KeyCommitment value is required for decryption
	if materials.KeyCommitment == nil {
		return nil, fmt.Errorf("key commitment is required for AES-GCM committing decryption")
	}

	return NewAESGCMCommittingContentCipher(materials)
}