package materials

import (
	"context"
	"fmt"
	"log"
)

type CryptographicMaterialsManager interface {
	GetEncryptionMaterials(ctx context.Context, matDesc MaterialDescription) (*CryptographicMaterials, error)
	DecryptMaterials(ctx context.Context, req DecryptMaterialsRequest) (*CryptographicMaterials, error)
}

// DefaultCryptographicMaterialsManager is a collection of registries for configuring a encryption client with different Keyring algorithms,
// content encryption algorithms, and padders.
type DefaultCryptographicMaterialsManager struct {
	Keyring *Keyring
}

// NewCryptographicMaterialsManager creates a new DefaultCryptographicMaterialsManager to which Keyrings, content encryption ciphers, and
// padders can be registered for use with the S3EncryptionClientV3.
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

func (cmm *DefaultCryptographicMaterialsManager) GetEncryptionMaterials(ctx context.Context, matDesc MaterialDescription) (*CryptographicMaterials, error) {
	keyring := *cmm.Keyring
	encryptionMaterials := NewEncryptionMaterials()
	encryptionMaterials.encryptionContext = matDesc

	return keyring.OnEncrypt(ctx, encryptionMaterials)
}

type DecryptMaterialsRequest struct {
	CipherKey  []byte
	Iv         []byte
	MatDesc    string
	KeyringAlg string
	CekAlg     string
	TagLength  string
}

func (cmm *DefaultCryptographicMaterialsManager) DecryptMaterials(ctx context.Context, req DecryptMaterialsRequest) (*CryptographicMaterials, error) {
	keyring := *cmm.Keyring

	materials, err := NewDecryptionMaterials(req)
	if err != nil {
		return nil, err
	}
	return keyring.OnDecrypt(ctx, materials, materials.DataKey)
}