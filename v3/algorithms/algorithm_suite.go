// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package algorithms

import (
	"crypto/sha512"
	"fmt"
	"strconv"
	"hash"
)

// Algorithm constants
const (
	// GCM maximum content length in bits (2^39 - 256 bits)
	GCMMaxContentLengthBits = 549755813632
	// CTR maximum content length in bytes (2^32 bytes)
	CTRMaxContentLengthBytes = 4294967296
	// CBC maximum content length in bytes (2^32 bytes)  
	CBCMaxContentLengthBytes = 4294967296
	
	// Algorithm identifiers
	AESGCMCommitKey = "115"
	AESGCMNoPadding = "AES/GCM/NoPadding"
	AESCTRNoPadding = "AES/CTR/NoPadding"
	AESCBCPKCS5   	= "AES/CBC/PKCS5Padding"
)

// AlgorithmSuite represents the encryption algorithm suite configuration
type AlgorithmSuite struct {
	id                         int
	isLegacy                   bool
	dataKeyAlgorithm          string
	dataKeyLengthBits         int
	cipherName                string
	cipherBlockSizeBits       int
	cipherIvLengthBits        int
	cipherTagLengthBits       int
	cipherMaxContentLengthBits int64
	isCommitting              bool
	commitmentLengthBits      int
	kdfHashAlgorithm          func() hash.Hash
}

// Predefined algorithm suites
var (
	// Key committing AES-256-GCM content encryption with HKDF-SHA512 commitment/encryption key derivation.
	// In addition to the security properties for the AES-256-GCM content encryption suite,
	// this suite also uses HKDF to derive a key commitment string that is included in metadata.
	// v3 clients (only v3.2.0 or higher) can only use this suite to read objects with key commitment;
	// to use this suite to write objects with key commitment, upgrade to a v4 client.
	AlgAES256GCMHkdfSha512CommitKey = &AlgorithmSuite{
		id:                         0x0073,
		isLegacy:                   false,
		dataKeyAlgorithm:          "AES",
		dataKeyLengthBits:         256, // this is the input into the KDF
		cipherName:                AESGCMCommitKey,
		cipherBlockSizeBits:       128,
		cipherIvLengthBits:        224,
		cipherTagLengthBits:       128,
		cipherMaxContentLengthBits: GCMMaxContentLengthBits,
		isCommitting:              true,
		commitmentLengthBits:      224,
		kdfHashAlgorithm:          sha512.New,
	}

	// AES-256 GCM content encryption.
	// This suite uses the data encryption key directly for AES-256 GCM content encryption.
	// This is the default suite for v3 clients.
	// Content encrypted with this suite can be read by any v2, v3, or v4 client.
	AlgAES256GCMIV12Tag16NoKDF = &AlgorithmSuite{
		id:                         0x0072,
		isLegacy:                   false,
		dataKeyAlgorithm:          "AES",
		dataKeyLengthBits:         256,
		cipherName:                AESGCMNoPadding,
		cipherBlockSizeBits:       128,
		cipherIvLengthBits:        96,
		cipherTagLengthBits:       128,
		cipherMaxContentLengthBits: GCMMaxContentLengthBits,
		isCommitting:              false,
		commitmentLengthBits:      0,
		kdfHashAlgorithm:          nil,
	}

	// Legacy AES-256 CTR.
	// This suite is not supported at this time.
	AlgAES256CTRIV16Tag16NoKDF = &AlgorithmSuite{
		id:                         0x0071,
		isLegacy:                   true,
		dataKeyAlgorithm:          "AES",
		dataKeyLengthBits:         256,
		cipherName:                AESCTRNoPadding,
		cipherBlockSizeBits:       128,
		cipherIvLengthBits:        128,
		cipherTagLengthBits:       128,
		cipherMaxContentLengthBits: CTRMaxContentLengthBytes * 8,
		isCommitting:              false,
		commitmentLengthBits:      0,
		kdfHashAlgorithm:          nil,
	}

	// Legacy AES-256 CBC.
	// This suite is only supported for decryption of existing objects and cannot be used for new objects.
	// We recommend migrating any existing objects encrypted with this suite to a non-legacy suite.
	AlgAES256CBCIV16NoKDF = &AlgorithmSuite{
		id:                         0x0070,
		isLegacy:                   true,
		dataKeyAlgorithm:          "AES",
		dataKeyLengthBits:         256,
		cipherName:                AESCBCPKCS5,
		cipherBlockSizeBits:       128,
		cipherIvLengthBits:        128,
		cipherTagLengthBits:       0,
		cipherMaxContentLengthBits: CBCMaxContentLengthBytes * 8,
		isCommitting:              false,
		commitmentLengthBits:      0,
		kdfHashAlgorithm:          nil,
	}
)

// Map for looking up algorithm suites by ID
var algorithmSuitesByID = map[int]*AlgorithmSuite{
	0x0073: AlgAES256GCMHkdfSha512CommitKey,
	0x0072: AlgAES256GCMIV12Tag16NoKDF,
	0x0071: AlgAES256CTRIV16Tag16NoKDF,
	0x0070: AlgAES256CBCIV16NoKDF,
}

// GetAlgorithmSuiteByID returns the algorithm suite for the given ID
func GetAlgorithmSuiteByID(id int) (*AlgorithmSuite, error) {
	suite, exists := algorithmSuitesByID[id]
	if !exists {
		return nil, fmt.Errorf("unknown algorithm suite ID: 0x%04x", id)
	}
	return suite, nil
}

// ID returns the algorithm suite ID
func (a *AlgorithmSuite) ID() int {
	return a.id
}

// IDAsString returns the algorithm suite ID as a string
func (a *AlgorithmSuite) IDAsString() string {
	return strconv.Itoa(a.id)
}

// IDAsBytes returns the algorithm suite ID as a byte array (big-endian)
func (a *AlgorithmSuite) IDAsBytes() []byte {
	return []byte{byte(a.id >> 8), byte(a.id)}
}

// IsLegacy returns whether this is a legacy algorithm suite
func (a *AlgorithmSuite) IsLegacy() bool {
	return a.isLegacy
}

// DataKeyAlgorithm returns the data key algorithm name
func (a *AlgorithmSuite) DataKeyAlgorithm() string {
	return a.dataKeyAlgorithm
}

// DataKeyLengthBits returns the data key length in bits
func (a *AlgorithmSuite) DataKeyLengthBits() int {
	return a.dataKeyLengthBits
}

// DataKeyLengthBytes returns the data key length in bytes
func (a *AlgorithmSuite) DataKeyLengthBytes() int {
	return a.dataKeyLengthBits / 8
}

// CipherName returns the cipher name
func (a *AlgorithmSuite) CipherName() string {
	return a.cipherName
}

// CipherTagLengthBits returns the cipher tag length in bits
func (a *AlgorithmSuite) CipherTagLengthBits() int {
	return a.cipherTagLengthBits
}

// CipherTagLengthBytes returns the cipher tag length in bytes
func (a *AlgorithmSuite) CipherTagLengthBytes() int {
	return a.cipherTagLengthBits / 8
}

// IVLengthBytes returns the IV length in bytes
func (a *AlgorithmSuite) IVLengthBytes() int {
	return a.cipherIvLengthBits / 8
}

// CipherBlockSizeBytes returns the cipher block size in bytes
func (a *AlgorithmSuite) CipherBlockSizeBytes() int {
	return a.cipherBlockSizeBits / 8
}

// CipherMaxContentLengthBits returns the maximum content length in bits
func (a *AlgorithmSuite) CipherMaxContentLengthBits() int64 {
	return a.cipherMaxContentLengthBits
}

// CipherMaxContentLengthBytes returns the maximum content length in bytes
func (a *AlgorithmSuite) CipherMaxContentLengthBytes() int64 {
	return a.cipherMaxContentLengthBits / 8
}

// IsCommitting returns whether this algorithm suite is key committing
func (a *AlgorithmSuite) IsCommitting() bool {
	return a.isCommitting
}

// CommitmentLengthBits returns the commitment length in bits
func (a *AlgorithmSuite) CommitmentLengthBits() int {
	return a.commitmentLengthBits
}

// CommitmentLengthBytes returns the commitment length in bytes
func (a *AlgorithmSuite) CommitmentLengthBytes() int {
	return a.commitmentLengthBits / 8
}

// KDFHashAlgorithm returns the KDF hash algorithm
func (a *AlgorithmSuite) KDFHashAlgorithm() func() hash.Hash {
	return a.kdfHashAlgorithm
}
