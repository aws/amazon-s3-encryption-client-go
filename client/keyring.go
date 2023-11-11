package client

import (
	"context"
	"crypto/rand"
	"github.com/aws/amazon-s3-encryption-client-go/internal"
)

// Keyring implementations are responsible for encrypting/decrypting data keys
// using some kind of key material.
// Keyring implementations MAY support decryption-only (i.e. for legacy algorithms)
// or both encryption (including data key generation) and decryption.
type Keyring interface {
	// OnEncrypt generates/encrypts a data key for use with content encryption
	OnEncrypt(ctx context.Context, materials *EncryptionMaterials) (*internal.CryptographicMaterials, error)
	// OnDecrypt decrypts the encryptedDataKeys and returns them in materials
	// for use with content decryption
	OnDecrypt(ctx context.Context, materials *DecryptionMaterials, encryptedDataKey DataKey) (*internal.CryptographicMaterials, error)
}

// CipherDataGenerator handles generating proper key and IVs of proper size for the
// content cipher. CipherDataGenerator will also encrypt the key and store it in
// the CryptographicMaterials.
type CipherDataGenerator interface {
	GenerateCipherData(int, int) (internal.CryptographicMaterials, error)
}

func generateBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
