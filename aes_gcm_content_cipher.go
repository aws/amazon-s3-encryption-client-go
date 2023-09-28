package s3crypto

import (
	"fmt"
	"io"
)

const (
	gcmKeySize   = 32
	gcmNonceSize = 12
)

// TODO: relocate or delete
// AESGCMContentCipherBuilder returns a new encryption only AES/GCM mode structure with a specific cipher data generator
// that will provide keys to be used for content encryption.
//
// Note: This uses the Go stdlib AEAD implementation for AES/GCM. Due to this objects to be encrypted or decrypted
// will be fully loaded into memory before encryption or decryption can occur. Caution must be taken to avoid memory
// allocation failures.
//func AESGCMContentCipherBuilder(generator CipherDataGeneratorWithCEKAlg) ContentCipherBuilder {
//	return gcmContentCipherBuilder{generator}
//}

// RegisterAESGCMContentCipher registers the AES/GCM content cipher algorithm with the provided DefaultCryptographicMaterialsManager.
//
// Example:
//
//	cr := s3crypto.NewCryptographicMaterialsManager()
//	if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
//		panic(err) // handle error
//	}
func RegisterAESGCMContentCipher(registry *DefaultCryptographicMaterialsManager) error {
	if registry == nil {
		return errNilCryptographicMaterialsManager
	}

	err := registry.AddCEK(AESGCMNoPadding, newAESGCMContentCipher)
	if err != nil {
		return err
	}

	// NoPadder is generic but required by this algorithm, so if it is already registered and is the expected implementation
	// don't error.
	padderName := NoPadder.Name()
	if v, ok := registry.GetPadder(padderName); !ok {
		if err := registry.AddPadder(padderName, NoPadder); err != nil {
			return err
		}
	} else if _, ok := v.(noPadder); !ok {
		return fmt.Errorf("%s is already registred but does not match expected type %T", padderName, NoPadder)
	}
	return nil
}

// TODO: Relocate
// isAWSFixture will return whether this type was constructed with an AWS provided CipherDataGenerator
//func (builder gcmContentCipherBuilder) isAWSFixture() bool {
//	v, ok := builder.generator.(awsFixture)
//	return ok && v.isAWSFixture()
//}

func newAESGCMContentCipher(cd CryptographicMaterials) (ContentCipher, error) {
	cd.CEKAlgorithm = AESGCMNoPadding
	cd.TagLength = "128"

	cipher, err := newAESGCM(cd)
	if err != nil {
		return nil, err
	}

	return &aesGCMContentCipher{
		CipherData: cd,
		Cipher:     cipher,
	}, nil
}

// AESGCMContentCipher will use AES GCM for the main cipher.
type aesGCMContentCipher struct {
	CipherData CryptographicMaterials
	Cipher     Cipher
}

// EncryptContents will generate a random key and iv and encrypt the data using cbc
func (cc *aesGCMContentCipher) EncryptContents(src io.Reader) (io.Reader, error) {
	return cc.Cipher.Encrypt(src), nil
}

// DecryptContents will use the symmetric key provider to instantiate a new GCM cipher.
// We grab a decrypt reader from gcm and wrap it in a CryptoReadCloser. The only error
// expected here is when the key or iv is of invalid length.
func (cc *aesGCMContentCipher) DecryptContents(src io.ReadCloser) (io.ReadCloser, error) {
	reader := cc.Cipher.Decrypt(src)
	return &CryptoReadCloser{Body: src, Decrypter: reader}, nil
}

// GetCipherData returns cipher data
func (cc aesGCMContentCipher) GetCipherData() CryptographicMaterials {
	return cc.CipherData
}

// TODO: figure out what the point of this is, relocate if needed
// assert ContentCipherBuilder implementations
//var (
//	_ ContentCipherBuilder = (*gcmContentCipherBuilder)(nil)
//)
//
//// assert ContentCipherBuilderWithContext implementations
//var (
//	_ ContentCipherBuilderWithContext = (*gcmContentCipherBuilder)(nil)
//)

// assert ContentCipher implementations
var (
	_ ContentCipher = (*aesGCMContentCipher)(nil)
)

//// assert awsFixture implementations
//var (
//	_ awsFixture = (*gcmContentCipherBuilder)(nil)
//)
