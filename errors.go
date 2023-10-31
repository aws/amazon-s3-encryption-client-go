package s3crypto

import "fmt"

var errNilCryptographicMaterialsManager = fmt.Errorf("provided DefaultCryptographicMaterialsManager must not be nil")
var errNilKeyringEntry = fmt.Errorf("keyring entry must not be nil")
var errNilCEKEntry = fmt.Errorf("cek entry must not be nil")
var errNilPadder = fmt.Errorf("padder must not be nil")

func newErrDuplicateKeyringEntry(name string) error {
	return newErrDuplicateRegistryEntry("KeyringEntry", name)
}

func newErrDuplicateCEKEntry(name string) error {
	return newErrDuplicateRegistryEntry("cek", name)
}

func newErrDuplicatePadderEntry(name string) error {
	return newErrDuplicateRegistryEntry("padder", name)
}

func newErrDuplicateRegistryEntry(registry, key string) error {
	return fmt.Errorf("duplicate %v registry entry, %v", registry, key)
}
