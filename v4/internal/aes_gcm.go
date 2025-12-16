// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"bytes"
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v4/algorithms"
	"io"
)

// AESGCM Symmetric encryption algorithm. Since Golang designed this
// with only TLS in mind. We have to load it all into memory meaning
// this isn't streamed.
type aesGCM struct {
	aead  cipher.AEAD
	nonce []byte
	aad  []byte
}

// newAESGCM creates a new AES GCM cipher. Expects keys to be of
// the correct size.
//
// Example:
//
//	materials := &s3crypto.CryptographicMaterials{
//		Key: key,
//		"IV": iv,
//	}
//	cipher, err := s3crypto.newAESGCM(materials)
func newAESGCM(materials materials.CryptographicMaterials) (Cipher, error) {
	expectedNonceLength := algorithms.AlgAES256GCMIV12Tag16NoKDF.IVLengthBytes()
	if len(materials.IV) != expectedNonceLength {
		return nil, fmt.Errorf("invalid nonce length: expected %d bytes, got %d bytes for algorithm %s", expectedNonceLength, len(materials.IV), materials.CEKAlgorithm)
	}
	
	block, err := aes.NewCipher(materials.Key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if materials.CEKAlgorithm == algorithms.AESGCMCommitKey {
		//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
		//# The client MUST set the AAD to the Algorithm Suite ID represented as bytes.
		aad := algorithms.AlgAES256GCMHkdfSha512CommitKey.IDAsBytes()
		return &aesGCM{aesgcm, materials.IV, aad}, nil
	} else if materials.CEKAlgorithm == algorithms.AESGCMNoPadding {
		//= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
		//# The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
		return &aesGCM{aesgcm, materials.IV, nil}, nil
	} else {
		return nil, fmt.Errorf("unsupported CEK algorithm for AES GCM: %s", materials.CEKAlgorithm)
	}
	
}

// Encrypt will encrypt the data using AES GCM
// Tag will be included as the last 16 bytes of the slice
func (c *aesGCM) Encrypt(src io.Reader) io.Reader {
	reader := &gcmEncryptReader{
		encrypter: c.aead,
		nonce:     c.nonce,
		src:       src,
		aad:	   c.aad,
	}
	return reader
}

type gcmEncryptReader struct {
	encrypter cipher.AEAD
	nonce     []byte
	src       io.Reader
	buf       *bytes.Buffer
	aad	      []byte
}

func (reader *gcmEncryptReader) Read(data []byte) (int, error) {
	if reader.buf == nil {
		b, err := io.ReadAll(reader.src)
		if err != nil {
			return 0, err
		}
		var aad []byte
		if reader.aad != nil {
			aad = reader.aad
		} else {
			aad = nil
		}
		// The GCM auth tag is appended to the ciphertext by the Seal function.
		// Docs: https://pkg.go.dev/crypto/cipher#GCM
		//= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
		//= type=exception
		//# The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.
		//= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
		//= type=exception
		//# The client MUST append the GCM auth tag to the ciphertext if the underlying crypto provider does not do so automatically.

		//= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
		//= type=implication
		//# The client MUST initialize the cipher, or call an AES-GCM encryption API,
		//# with the plaintext data key, the generated IV, and the tag length defined in the Algorithm Suite
		//# when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
		b = reader.encrypter.Seal(b[:0], reader.nonce, b, aad)
		reader.buf = bytes.NewBuffer(b)
	}

	return reader.buf.Read(data)
}

// Decrypt will decrypt the data using AES GCM
func (c *aesGCM) Decrypt(src io.Reader) io.Reader {
	return &gcmDecryptReader{
		decrypter: c.aead,
		nonce:     c.nonce,
		src:       src,
		aad:	   c.aad,
	}
}

type gcmDecryptReader struct {
	decrypter cipher.AEAD
	nonce     []byte
	src       io.Reader
	buf       *bytes.Buffer
	aad 	  []byte
}

func (reader *gcmDecryptReader) Read(data []byte) (int, error) {
	var aad []byte
	if reader.aad != nil {
		aad = reader.aad
	} else {
		aad = nil
	}
	if reader.buf == nil {
		b, err := io.ReadAll(reader.src)
		if err != nil {
			return 0, err
		}
		b, err = reader.decrypter.Open(b[:0], reader.nonce, b, aad)
		if err != nil {
			return 0, err
		}

		reader.buf = bytes.NewBuffer(b)
	}

	return reader.buf.Read(data)
}
