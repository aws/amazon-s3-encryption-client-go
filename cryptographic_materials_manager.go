package s3crypto

import (
	"fmt"
)

// KeyringEntry is builder that return a proper key decrypter and error
type KeyringEntry func(Envelope) (CipherDataDecrypter, error)

// CEKEntry is a builder that returns a proper content decrypter and error
type CEKEntry func(CipherData) (ContentCipher, error)

// CryptographicMaterialsManager is a collection of registries for configuring a encryption client with different Keyring algorithms,
// content encryption algorithms, and padders.
type CryptographicMaterialsManager struct {
	Keyring map[string]KeyringEntry
	cek     map[string]CEKEntry
	padder  map[string]Padder
}

// NewCryptographicMaterialsManager creates a new CryptographicMaterialsManager to which Keyrings, content encryption ciphers, and
// padders can be registered for use with the S3EncryptionClientV3.
func NewCryptographicMaterialsManager() *CryptographicMaterialsManager {
	return &CryptographicMaterialsManager{
		Keyring: map[string]KeyringEntry{},
		cek:     map[string]CEKEntry{},
		padder:  map[string]Padder{},
	}
}

// TODO: is this still useful in v3?
// initCryptographicMaterialsManagerFrom creates a CryptographicMaterialsManager from prepopulated values, this is used for the V1 client
func initCryptographicMaterialsManagerFrom(KeyringRegistry map[string]KeyringEntry, cekRegistry map[string]CEKEntry, padderRegistry map[string]Padder) *CryptographicMaterialsManager {
	cr := &CryptographicMaterialsManager{
		Keyring: KeyringRegistry,
		cek:     cekRegistry,
		padder:  padderRegistry,
	}
	return cr
}

// GetKeyring returns the KeyringEntry identified by the given name. Returns false if the entry is not registered.
func (c CryptographicMaterialsManager) GetKeyring(name string) (KeyringEntry, bool) {
	if c.Keyring == nil {
		return nil, false
	}
	entry, ok := c.Keyring[name]
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
func (c *CryptographicMaterialsManager) AddKeyring(name string, entry KeyringEntry) error {
	if entry == nil {
		return errNilKeyringEntry
	}

	if _, ok := c.Keyring[name]; ok {
		return newErrDuplicateKeyringEntry(name)
	}
	c.Keyring[name] = entry
	return nil
}

// RemoveKeyring removes the KeyringEntry identified by name. If the KeyringEntry is not present returns false.
func (c *CryptographicMaterialsManager) RemoveKeyring(name string) (KeyringEntry, bool) {
	if c.Keyring == nil {
		return nil, false
	}
	entry, ok := c.Keyring[name]
	if ok {
		delete(c.Keyring, name)
	}
	return entry, ok
}

// GetCEK returns the CEKEntry identified by the given name. Returns false if the entry is not registered.
func (c CryptographicMaterialsManager) GetCEK(name string) (CEKEntry, bool) {
	if c.cek == nil {
		return nil, false
	}
	entry, ok := c.cek[name]
	return entry, ok
}

// AddCEK registers CEKEntry under the given name, returns an error if a CEKEntry is already present for the given name.
//
// This method should only be used if you need to register custom content encryption algorithms. Please see the following methods
// for helpers to register AWS provided algorithms:
//
//	RegisterAESGCMContentCipher (AES/GCM)
//	RegisterAESCBCContentCipher (AES/CBC)
func (c *CryptographicMaterialsManager) AddCEK(name string, entry CEKEntry) error {
	if entry == nil {
		return errNilCEKEntry
	}
	if _, ok := c.cek[name]; ok {
		return newErrDuplicateCEKEntry(name)
	}
	c.cek[name] = entry
	return nil
}

// RemoveCEK removes the CEKEntry identified by name. If the entry is not present returns false.
func (c *CryptographicMaterialsManager) RemoveCEK(name string) (CEKEntry, bool) {
	if c.cek == nil {
		return nil, false
	}
	entry, ok := c.cek[name]
	if ok {
		delete(c.cek, name)
	}
	return entry, ok
}

// GetPadder returns the Padder identified by name. If the Padder is not present, returns false.
func (c *CryptographicMaterialsManager) GetPadder(name string) (Padder, bool) {
	if c.padder == nil {
		return nil, false
	}
	entry, ok := c.padder[name]
	return entry, ok
}

// AddPadder registers Padder under the given name, returns an error if a Padder is already present for the given name.
//
// This method should only be used to register custom padder implementations not provided by AWS.
func (c *CryptographicMaterialsManager) AddPadder(name string, padder Padder) error {
	if padder == nil {
		return errNilPadder
	}
	if _, ok := c.padder[name]; ok {
		return newErrDuplicatePadderEntry(name)
	}
	c.padder[name] = padder
	return nil
}

// RemovePadder removes the Padder identified by name. If the entry is not present returns false.
func (c *CryptographicMaterialsManager) RemovePadder(name string) (Padder, bool) {
	if c.padder == nil {
		return nil, false
	}
	padder, ok := c.padder[name]
	if ok {
		delete(c.padder, name)
	}
	return padder, ok
}

func (c CryptographicMaterialsManager) valid() error {
	if len(c.Keyring) == 0 {
		return fmt.Errorf("at least one Keyring must be provided")
	}
	if len(c.cek) == 0 {
		return fmt.Errorf("at least one content decryption algorithms must be provided")
	}
	return nil
}
