// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"
	"fmt"
	"log"
)

// CryptographicMaterialsManager (CMM) assembles the cryptographic materials used to
// encrypt and decrypt the encrypted objects.
type CryptographicMaterialsManager interface {
	GetEncryptionMaterials(ctx context.Context, matDesc MaterialDescription) (*CryptographicMaterials, error)
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
func (cmm *DefaultCryptographicMaterialsManager) GetEncryptionMaterials(ctx context.Context, matDesc MaterialDescription) (*CryptographicMaterials, error) {
	keyring := *cmm.Keyring
	encryptionMaterials := NewEncryptionMaterials()
	encryptionMaterials.encryptionContext = matDesc

	return keyring.OnEncrypt(ctx, encryptionMaterials)
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
