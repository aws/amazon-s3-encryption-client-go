package s3crypto

import (
	"context"
	"fmt"
)

// KeyringEntry is builder that return a proper key decrypter and error
type KeyringEntry func(ObjectMetadata) (CipherDataDecrypter, error)

// CEKEntry is a builder that returns a proper content decrypter and error
type CEKEntry func(CryptographicMaterials) (ContentCipher, error)

// CryptographicMaterialsManager is a collection of registries for configuring a encryption client with different Keyring algorithms,
// content encryption algorithms, and padders.
type CryptographicMaterialsManager struct {
	KeyringEntry        map[string]KeyringEntry
	cek                 map[string]CEKEntry
	padder              map[string]Padder
	GeneratorWithCEKAlg *CipherDataGeneratorWithCEKAlg
	Keyring             *Keyring
}

// NewCryptographicMaterialsManager creates a new CryptographicMaterialsManager to which Keyrings, content encryption ciphers, and
// padders can be registered for use with the S3EncryptionClientV3.
func NewCryptographicMaterialsManager(generatorWithCEKAlg *CipherDataGeneratorWithCEKAlg, keyring Keyring) (*CryptographicMaterialsManager, error) {
	cmm := &CryptographicMaterialsManager{
		KeyringEntry:        map[string]KeyringEntry{},
		cek:                 map[string]CEKEntry{},
		padder:              map[string]Padder{},
		GeneratorWithCEKAlg: generatorWithCEKAlg,
		Keyring:             &keyring,
	}
	err := cmm.AddCEK(AESGCMNoPadding, newAESGCMContentCipher)
	if err != nil {
		return nil, err
	}

	return cmm, nil
}

// TODO: is this still useful in v3?
// initCryptographicMaterialsManagerFrom creates a CryptographicMaterialsManager from prepopulated values, this is used for the V1 client
func initCryptographicMaterialsManagerFrom(KeyringRegistry map[string]KeyringEntry, cekRegistry map[string]CEKEntry, padderRegistry map[string]Padder) *CryptographicMaterialsManager {
	cr := &CryptographicMaterialsManager{
		KeyringEntry: KeyringRegistry,
		cek:          cekRegistry,
		padder:       padderRegistry,
	}
	return cr
}

// GetKeyring returns the KeyringEntry identified by the given name. Returns false if the entry is not registered.
func (cmm CryptographicMaterialsManager) GetKeyring(name string) (KeyringEntry, bool) {
	if cmm.KeyringEntry == nil {
		return nil, false
	}
	entry, ok := cmm.KeyringEntry[name]
	return entry, ok
}

// AddKeyring registers the provided KeyringEntry under the given name, returns an error if a KeyringEntry is already present
// for the given name.
//
// This method should only be used if you need to register custom Keyring entries. Please see the following methods
// for helpers to register AWS provided algorithms:
//
//	RegisterKMSContextKeyringWithAnyCMK (kms+context)
//	RegisterKMSContextKeyringWithCMK (kms+context)
//	RegisterKMSKeyringWithAnyCMK (kms)
//	RegisterKMSKeyringWithCMK (kms)
func (cmm *CryptographicMaterialsManager) AddKeyring(name string, entry KeyringEntry) error {
	if entry == nil {
		return errNilKeyringEntry
	}

	if _, ok := cmm.KeyringEntry[name]; ok {
		return newErrDuplicateKeyringEntry(name)
	}
	cmm.KeyringEntry[name] = entry
	return nil
}

// RemoveKeyring removes the KeyringEntry identified by name. If the KeyringEntry is not present returns false.
func (cmm *CryptographicMaterialsManager) RemoveKeyring(name string) (KeyringEntry, bool) {
	if cmm.KeyringEntry == nil {
		return nil, false
	}
	entry, ok := cmm.KeyringEntry[name]
	if ok {
		delete(cmm.KeyringEntry, name)
	}
	return entry, ok
}

// GetCEK returns the CEKEntry identified by the given name. Returns false if the entry is not registered.
func (cmm CryptographicMaterialsManager) GetCEK(name string) (CEKEntry, bool) {
	if cmm.cek == nil {
		return nil, false
	}
	entry, ok := cmm.cek[name]
	return entry, ok
}

// AddCEK registers CEKEntry under the given name, returns an error if a CEKEntry is already present for the given name.
//
// This method should only be used if you need to register custom content encryption algorithms. Please see the following methods
// for helpers to register AWS provided algorithms:
//
//	RegisterAESGCMContentCipher (AES/GCM)
//	RegisterAESCBCContentCipher (AES/CBC)
func (cmm *CryptographicMaterialsManager) AddCEK(name string, entry CEKEntry) error {
	if entry == nil {
		return errNilCEKEntry
	}
	if _, ok := cmm.cek[name]; ok {
		return newErrDuplicateCEKEntry(name)
	}
	cmm.cek[name] = entry
	return nil
}

// RemoveCEK removes the CEKEntry identified by name. If the entry is not present returns false.
func (cmm *CryptographicMaterialsManager) RemoveCEK(name string) (CEKEntry, bool) {
	if cmm.cek == nil {
		return nil, false
	}
	entry, ok := cmm.cek[name]
	if ok {
		delete(cmm.cek, name)
	}
	return entry, ok
}

// GetPadder returns the Padder identified by name. If the Padder is not present, returns false.
func (cmm *CryptographicMaterialsManager) GetPadder(name string) (Padder, bool) {
	if cmm.padder == nil {
		return nil, false
	}
	entry, ok := cmm.padder[name]
	return entry, ok
}

// AddPadder registers Padder under the given name, returns an error if a Padder is already present for the given name.
//
// This method should only be used to register custom padder implementations not provided by AWS.
func (cmm *CryptographicMaterialsManager) AddPadder(name string, padder Padder) error {
	if padder == nil {
		return errNilPadder
	}
	if _, ok := cmm.padder[name]; ok {
		return newErrDuplicatePadderEntry(name)
	}
	cmm.padder[name] = padder
	return nil
}

// RemovePadder removes the Padder identified by name. If the entry is not present returns false.
func (cmm *CryptographicMaterialsManager) RemovePadder(name string) (Padder, bool) {
	if cmm.padder == nil {
		return nil, false
	}
	padder, ok := cmm.padder[name]
	if ok {
		delete(cmm.padder, name)
	}
	return padder, ok
}

type EncryptionMaterials struct {
	gcmKeySize   int
	gcmNonceSize int
	algorithm    string
}

func NewEncryptionMaterials() *EncryptionMaterials {
	return &EncryptionMaterials{
		gcmKeySize:   gcmKeySize,
		gcmNonceSize: gcmNonceSize,
		algorithm:    AESGCMNoPadding,
	}
}

func (cmm *CryptographicMaterialsManager) getEncryptionMaterials() *EncryptionMaterials {
	return NewEncryptionMaterials()
}

func (cmm *CryptographicMaterialsManager) decryptMaterials(ctx context.Context, objectMetadata ObjectMetadata) (*CryptographicMaterials, error) {
	keyring := *cmm.Keyring
	materials, err := NewDecryptionMaterials(objectMetadata.CipherKey, objectMetadata.IV, objectMetadata.MatDesc, objectMetadata.CEKAlg)
	if err != nil {
		return nil, err
	}
	return keyring.OnDecrypt(ctx, materials, materials.DataKey)
}

func (cmm CryptographicMaterialsManager) valid() error {
	if len(cmm.KeyringEntry) == 0 {
		return fmt.Errorf("at least one KeyringEntry must be provided")
	}
	if len(cmm.cek) == 0 {
		return fmt.Errorf("at least one content decryption algorithms must be provided")
	}
	return nil
}
