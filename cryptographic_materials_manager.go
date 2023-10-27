package s3crypto

import (
	"context"
	"fmt"
	"log"
)

// CEKEntry is a builder that returns a proper content decrypter and error
type CEKEntry func(CryptographicMaterials) (ContentCipher, error)

type CryptographicMaterialsManager interface {
	getEncryptionMaterials() *EncryptionMaterials
	decryptMaterials(ctx context.Context, objectMetadata ObjectMetadata) (*CryptographicMaterials, error)
	GetKeyring() Keyring
}

// DefaultCryptographicMaterialsManager is a collection of registries for configuring a encryption client with different Keyring algorithms,
// content encryption algorithms, and padders.
type DefaultCryptographicMaterialsManager struct {
	cek     map[string]CEKEntry
	padder  map[string]Padder
	Keyring *Keyring
}

// NewCryptographicMaterialsManager creates a new DefaultCryptographicMaterialsManager to which Keyrings, content encryption ciphers, and
// padders can be registered for use with the S3EncryptionClientV3.
func NewCryptographicMaterialsManager(keyring Keyring) (*DefaultCryptographicMaterialsManager, error) {
	cmm := &DefaultCryptographicMaterialsManager{
		cek:     map[string]CEKEntry{},
		padder:  map[string]Padder{},
		Keyring: &keyring,
	}
	if keyring != nil {
		// Check if the passed in type is a fixture, if not log a warning message to the user
		if fixture, ok := keyring.(awsFixture); !ok || !fixture.isAWSFixture() {
			log.Default().Println(customTypeWarningMessage)
		}
	}

	return cmm, nil
}

// GetKeyring returns the KeyringEntry identified by the given name. Returns false if the entry is not registered.
func (cmm DefaultCryptographicMaterialsManager) GetKeyring() Keyring {
	return *cmm.Keyring
}

func (cmm *DefaultCryptographicMaterialsManager) getEncryptionMaterials() *EncryptionMaterials {
	return NewEncryptionMaterials()
}

func (cmm *DefaultCryptographicMaterialsManager) decryptMaterials(ctx context.Context, objectMetadata ObjectMetadata) (*CryptographicMaterials, error) {
	keyring := *cmm.Keyring

	materials, err := NewDecryptionMaterials(objectMetadata, cmm.padder)
	if err != nil {
		return nil, err
	}
	return keyring.OnDecrypt(ctx, materials, materials.DataKey)
}

func (cmm DefaultCryptographicMaterialsManager) valid() error {
	if len(cmm.cek) == 0 {
		return fmt.Errorf("at least one content decryption algorithms must be provided")
	}
	return nil
}
