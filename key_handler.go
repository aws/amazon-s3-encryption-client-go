package s3crypto

import (
	"context"
	"crypto/rand"
)

// CipherDataGenerator handles generating proper key and IVs of proper size for the
// content cipher. CipherDataGenerator will also encrypt the key and store it in
// the CipherData.
type CipherDataGenerator interface {
	GenerateCipherData(int, int) (CipherData, error)
}

// CipherDataGeneratorWithContext handles generating proper key and IVs of
// proper size for the content cipher. CipherDataGenerator will also encrypt
// the key and store it in the CipherData.
type CipherDataGeneratorWithContext interface {
	GenerateCipherDataWithContext(context.Context, int, int) (CipherData, error)
}

// CipherDataGeneratorWithCEKAlg handles generating proper key and IVs of proper size for the
// content cipher. CipherDataGenerator will also encrypt the key and store it in
// the CipherData.
type CipherDataGeneratorWithCEKAlg interface {
	GenerateCipherDataWithCEKAlg(ctx context.Context, keySize, ivSize int, cekAlgorithm string) (CipherData, error)
}

// CipherDataDecrypter is a handler to decrypt keys from the envelope.
type CipherDataDecrypter interface {
	DecryptKey([]byte) ([]byte, error)
}

// CipherDataDecrypterWithContext is a handler to decrypt keys from the envelope with request context.
type CipherDataDecrypterWithContext interface {
	DecryptKeyWithContext(context.Context, []byte) ([]byte, error)
}

func generateBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
