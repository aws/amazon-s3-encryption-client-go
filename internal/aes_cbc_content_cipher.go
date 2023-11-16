// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"io"
)

const (
	AESCBCPKCS5Padding = "AES/CBC/PKCS5Padding"
	aesCbcTagSizeBits  = "0"
)

// NewAESCBCContentCipher will create a new aes cbc content cipher. If the cipher data's
// will set the cek algorithm if it hasn't been set.
func NewAESCBCContentCipher(materials materials.CryptographicMaterials) (ContentCipher, error) {
	materials.TagLength = aesCbcTagSizeBits
	if len(materials.CEKAlgorithm) == 0 {
		materials.CEKAlgorithm = AESCBCPKCS5Padding
	}
	cipher, err := newAESCBC(materials, AESCBCPadder)
	if err != nil {
		return nil, err
	}

	return &aesCBCContentCipher{
		CryptographicMaterials: materials,
		Cipher:                 cipher,
	}, nil
}

// aesCBCContentCipher will use AES CBC for the main cipher.
type aesCBCContentCipher struct {
	CryptographicMaterials materials.CryptographicMaterials
	Cipher                 Cipher
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
func (cc aesCBCContentCipher) GetCipherData() materials.CryptographicMaterials {
	return cc.CryptographicMaterials
}

var (
	_ ContentCipher = (*aesCBCContentCipher)(nil)
)
