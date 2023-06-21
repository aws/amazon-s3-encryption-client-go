package s3crypto

import (
	"io"
)

// RegisterAESCBCContentCipher registers the AES/CBC cipher and padder with the provided CryptoRegistry.
//
// Example:
//
//	cr := s3crypto.NewCryptoRegistry()
//	if err := s3crypto.RegisterAESCBCContentCipher(cr, s3crypto.AESCBCPadder); err != nil {
//		panic(err) // handle error
//	}
//
// deprecated: This feature is in maintenance mode, no new updates will be released. Please see https://docs.aws.amazon.com/general/latest/gr/aws_sdk_cryptography.html for more information.
func RegisterAESCBCContentCipher(registry *CryptoRegistry, padder Padder) error {
	if registry == nil {
		return errNilCryptoRegistry
	}
	name := AESCBC + "/" + padder.Name()
	err := registry.AddCEK(name, newAESCBCContentCipher)
	if err != nil {
		return err
	}
	if err := registry.AddPadder(name, padder); err != nil {
		return err
	}
	return nil
}

// newAESCBCContentCipher will create a new aes cbc content cipher. If the cipher data's
// will set the cek algorithm if it hasn't been set.
func newAESCBCContentCipher(cd CipherData) (ContentCipher, error) {
	if len(cd.CEKAlgorithm) == 0 {
		cd.CEKAlgorithm = AESCBC + "/" + cd.Padder.Name()
	}
	cipher, err := newAESCBC(cd, cd.Padder)
	if err != nil {
		return nil, err
	}

	return &aesCBCContentCipher{
		CipherData: cd,
		Cipher:     cipher,
	}, nil
}

// aesCBCContentCipher will use AES CBC for the main cipher.
type aesCBCContentCipher struct {
	CipherData CipherData
	Cipher     Cipher
}

// EncryptContents will generate a random key and iv and encrypt the data using cbc
func (cc *aesCBCContentCipher) EncryptContents(src io.Reader) (io.Reader, error) {
	return cc.Cipher.Encrypt(src), nil
}

// DecryptContents will use the symmetric key provider to instantiate a new CBC cipher.
// We grab a decrypt reader from CBC and wrap it in a CryptoReadCloser. The only error
// expected here is when the key or iv is of invalid length.
func (cc *aesCBCContentCipher) DecryptContents(src io.ReadCloser) (io.ReadCloser, error) {
	reader := cc.Cipher.Decrypt(src)
	return &CryptoReadCloser{Body: src, Decrypter: reader}, nil
}

// GetCipherData returns cipher data
func (cc aesCBCContentCipher) GetCipherData() CipherData {
	return cc.CipherData
}

var (
	_ ContentCipher = (*aesCBCContentCipher)(nil)
)
