package s3crypto

import (
	"fmt"
)

// WrapEntry is builder that return a proper key decrypter and error
type WrapEntry func(Envelope) (CipherDataDecrypter, error)

// CEKEntry is a builder that returns a proper content decrypter and error
type CEKEntry func(CipherData) (ContentCipher, error)

// CryptographicMaterialsManager is a collection of registries for configuring a decryption client with different key wrapping algorithms,
// content encryption algorithms, and padders.
type CryptographicMaterialsManager struct {
	wrap   map[string]WrapEntry
	cek    map[string]CEKEntry
	padder map[string]Padder
}

// NewCryptographicMaterialsManager creates a new CryptographicMaterialsManager to which wrapping algorithms, content encryption ciphers, and
// padders can be registered for use with the DecryptionClientV3.
func NewCryptographicMaterialsManager() *CryptographicMaterialsManager {
	return &CryptographicMaterialsManager{
		wrap:   map[string]WrapEntry{},
		cek:    map[string]CEKEntry{},
		padder: map[string]Padder{},
	}
}

// initCryptographicMaterialsManagerFrom creates a CryptographicMaterialsManager from prepopulated values, this is used for the V1 client
func initCryptographicMaterialsManagerFrom(wrapRegistry map[string]WrapEntry, cekRegistry map[string]CEKEntry, padderRegistry map[string]Padder) *CryptographicMaterialsManager {
	cr := &CryptographicMaterialsManager{
		wrap:   wrapRegistry,
		cek:    cekRegistry,
		padder: padderRegistry,
	}
	return cr
}

// GetWrap returns the WrapEntry identified by the given name. Returns false if the entry is not registered.
func (c CryptographicMaterialsManager) GetWrap(name string) (WrapEntry, bool) {
	if c.wrap == nil {
		return nil, false
	}
	entry, ok := c.wrap[name]
	return entry, ok
}

// AddWrap registers the provided WrapEntry under the given name, returns an error if a WrapEntry is already present
// for the given name.
//
// This method should only be used if you need to register custom wrapping algorithms. Please see the following methods
// for helpers to register AWS provided algorithms:
//
//	RegisterKMSContextWrapWithAnyCMK (kms+context)
//	RegisterKMSContextWrapWithCMK (kms+context)
//	RegisterKMSWrapWithAnyCMK (kms)
//	RegisterKMSWrapWithCMK (kms)
func (c *CryptographicMaterialsManager) AddWrap(name string, entry WrapEntry) error {
	if entry == nil {
		return errNilWrapEntry
	}

	if _, ok := c.wrap[name]; ok {
		return newErrDuplicateWrapEntry(name)
	}
	c.wrap[name] = entry
	return nil
}

// RemoveWrap removes the WrapEntry identified by name. If the WrapEntry is not present returns false.
func (c *CryptographicMaterialsManager) RemoveWrap(name string) (WrapEntry, bool) {
	if c.wrap == nil {
		return nil, false
	}
	entry, ok := c.wrap[name]
	if ok {
		delete(c.wrap, name)
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
	if len(c.wrap) == 0 {
		return fmt.Errorf("at least one key wrapping algorithms must be provided")
	}
	if len(c.cek) == 0 {
		return fmt.Errorf("at least one content decryption algorithms must be provided")
	}
	return nil
}
