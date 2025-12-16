// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v4/algorithms"
	"log"
)

// CryptographicMaterialsManager (CMM) assembles the cryptographic materials used to
// encrypt and decrypt the encrypted objects.
type CryptographicMaterialsManager interface {
	GetEncryptionMaterials(ctx context.Context, req EncryptionMaterialsRequest) (*CryptographicMaterials, error)
	DecryptMaterials(ctx context.Context, req DecryptMaterialsRequest) (*CryptographicMaterials, error)
}

// DefaultCryptographicMaterialsManager provides support for encrypting and decrypting S3 objects using
// the configured Keyring.
type DefaultCryptographicMaterialsManager struct {
	Keyring *Keyring
}

// NewCryptographicMaterialsManager creates a new DefaultCryptographicMaterialsManager with the given Keyring.
// The Keyring provided must not be nil. If Keyring is nil, NewCryptographicMaterialsManager will return error.
func NewCryptographicMaterialsManager(keyring Keyring) (*DefaultCryptographicMaterialsManager, error) {
	cmm := &DefaultCryptographicMaterialsManager{
		Keyring: &keyring,
	}
	if keyring != nil {
		// Check if the passed in type is a fixture, if not log a warning message to the user
		if fixture, ok := keyring.(awsFixture); !ok || !fixture.isAWSFixture() {
			log.Default().Println(customTypeWarningMessage)
		}
	} else {
		// keyring MUST NOT be nil
		return nil, fmt.Errorf("keyring provided to new cryptographic materials manager MUST NOT be nil")
	}

	return cmm, nil
}

// GetEncryptionMaterials assembles the required EncryptionMaterials and then calls Keyring.OnEncrypt
// to encrypt the materials.
func (cmm *DefaultCryptographicMaterialsManager) GetEncryptionMaterials(ctx context.Context, req EncryptionMaterialsRequest) (*CryptographicMaterials, error) {
	keyring := *cmm.Keyring
	encryptionMaterials := NewEncryptionMaterials(req.AlgorithmSuite)
	encryptionMaterials.encryptionContext = req.MaterialDescription
	return keyring.OnEncrypt(ctx, encryptionMaterials)
}

// EncryptionMaterialsRequest contains the information required to assemble the EncryptionMaterials which
// are used by Keyring.OnEncrypt to encrypt the data key.
type EncryptionMaterialsRequest struct {
	MaterialDescription MaterialDescription
	AlgorithmSuite     *algorithms.AlgorithmSuite
}

// DecryptMaterialsRequest contains the information required to assemble the DecryptionMaterials which
// are used by Keyring.OnDecrypt to decrypt the encrypted data key.
type DecryptMaterialsRequest struct {
	CipherKey  []byte
	Iv         []byte
	MatDesc    string
	KeyringAlg string
	CekAlg     string
	TagLength  string
	KeyCommitment []byte
}

// DecryptMaterials uses the provided DecryptMaterialsRequest to assemble DecryptionMaterials which
// are used by Keyring.OnDecrypt to decrypt the encrypted data key.
func (cmm *DefaultCryptographicMaterialsManager) DecryptMaterials(ctx context.Context, req DecryptMaterialsRequest) (*CryptographicMaterials, error) {
	keyring := *cmm.Keyring

	materials, err := NewDecryptionMaterials(req)
	if err != nil {
		return nil, err
	}
	return keyring.OnDecrypt(ctx, materials, materials.DataKey)
}
