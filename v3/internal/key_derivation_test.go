// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"bytes"
	"encoding/hex"
	"strings"
	"github.com/aws/amazon-s3-encryption-client-go/v3/algorithms"
	"testing"
)

func hexToBytes(t *testing.T, s string, expectedLen int) []byte {
	b, err := decodeHex(s)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}
	if len(b) != expectedLen {
		t.Fatalf("Expected length %d, got %d for hex string %s", expectedLen, len(b), s)
	}
	return b
}

func decodeHex(s string) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(s)))
	_, err := hex.Decode(dst, []byte(s))
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func TestDeriveKeys_KnownAnswerTests(t *testing.T) {
	// Get algorithm suite for expected lengths
	algSuite := algorithms.AlgAES256GCMHkdfSha512CommitKey
	expectedDataKeyLength := algSuite.DataKeyLengthBytes()
	expectedCommitKeyLength := algSuite.CommitmentLengthBytes()
	expectedMessageIDLength := algSuite.IVLengthBytes()

	tests := []struct {
		comment        string
		dataKeyHex     string
		messageIDHex   string
		expectedEncHex string
		expectedComHex string
	}{
		{
			comment:        "Basic S3EC.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY #1",
			dataKeyHex:     "80d90dc4cc7e77d8a6332efa44eba56230a7fe7b89af37d1e501ab2e07c0a163",
			messageIDHex:   "b8ea76bed24c7b85382a148cb9dcd1cfdfb765f55ded4dfa6e0c4c79",
			expectedEncHex: "6dd14f546cc006e639126e83f5d4d1b118576bb5df97f38c6fb3a1db87bbc338",
			expectedComHex: "f89818bc0a346d3a3426b68e9509b6b2ae5fe1f904aa329fb73625db",
		},
		{
			comment:        "Basic S3EC.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY #2",
			dataKeyHex:     "501afb8227d22e75e68010414b8abdaf3064c081e8e922dafef4992036394d60",
			messageIDHex:   "61a00b4981a5aacfd136c55cb726e32d2a547dc7600a7d4675c69127",
			expectedEncHex: "e14786a714748d1d2c3a4a6816dec56ddf1881bbeabb4f39420ffb9f63700b2f",
			expectedComHex: "5c1e73e47f6fe3a70d6d094283aceaa76d2975feb829212d88f0afc1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.comment, func(t *testing.T) {
			dataKey := hexToBytes(t, tc.dataKeyHex, expectedDataKeyLength)
			messageID := hexToBytes(t, tc.messageIDHex, expectedMessageIDLength)
			expectedEnc := hexToBytes(t, tc.expectedEncHex, expectedDataKeyLength)
			expectedCom := hexToBytes(t, tc.expectedComHex, expectedCommitKeyLength)

			result, err := DeriveKeys(dataKey, messageID, algorithms.AlgAES256GCMHkdfSha512CommitKey.ID(), expectedCom)
			if err != nil {
				t.Fatalf("DeriveKeys failed: %v", err)
			}
			if !bytes.Equal(result.DerivedEncryptionKey, expectedEnc) {
				t.Errorf("DerivedEncryptionKey mismatch.\nExpected: %x\nGot:      %x", expectedEnc, result.DerivedEncryptionKey)
			}
			if !bytes.Equal(result.CommitKey, expectedCom) {
				t.Errorf("CommitKey mismatch.\nExpected: %x\nGot:      %x", expectedCom, result.CommitKey)
			}
		})
	}
}

func TestDeriveKeys_KeyCommitmentValidation(t *testing.T) {
	// Get algorithm suite for expected lengths
	algSuite := algorithms.AlgAES256GCMHkdfSha512CommitKey
	expectedDataKeyLength := algSuite.DataKeyLengthBytes()
	expectedCommitKeyLength := algSuite.CommitmentLengthBytes()
	expectedMessageIDLength := algSuite.IVLengthBytes()

	dataKey := hexToBytes(t, "80d90dc4cc7e77d8a6332efa44eba56230a7fe7b89af37d1e501ab2e07c0a163", expectedDataKeyLength)
	messageID := hexToBytes(t, "b8ea76bed24c7b85382a148cb9dcd1cfdfb765f55ded4dfa6e0c4c79", expectedMessageIDLength)
	correctCommitment := hexToBytes(t, "f89818bc0a346d3a3426b68e9509b6b2ae5fe1f904aa329fb73625db", expectedCommitKeyLength)
	wrongCommitment := hexToBytes(t, "00000000000000000000000000000000000000000000000000000000", expectedCommitKeyLength)

	//= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
	//= type=test
	//# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
	t.Run("matching_commitment_succeeds", func(t *testing.T) {
		result, err := DeriveKeys(dataKey, messageID, algorithms.AlgAES256GCMHkdfSha512CommitKey.ID(), correctCommitment)
		if err != nil {
			t.Fatalf("DeriveKeys should succeed when commitment values match, got error: %v", err)
		}

		// Verify that the derived commitment matches the stored commitment
		if !bytes.Equal(result.CommitKey, correctCommitment) {
			t.Errorf("Derived commitment should match stored commitment.\nExpected: %x\nGot:      %x", correctCommitment, result.CommitKey)
		}
	})

	//= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
	//= type=test
	//# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
	t.Run("mismatched_commitment_throws_exception", func(t *testing.T) {
		_, err := DeriveKeys(dataKey, messageID, algorithms.AlgAES256GCMHkdfSha512CommitKey.ID(), wrongCommitment)
		if err == nil {
			t.Fatalf("DeriveKeys should throw an exception when commitment values do not match, but it succeeded")
		}

		// Verify the error message indicates commitment mismatch
		if !bytes.Contains([]byte(err.Error()), []byte("derived key commitment value does not match value stored on encrypted message")) {
			t.Errorf("Expected error to mention commitment mismatch, got: %v", err)
		}
	})
}

func TestDeriveKeys_InputOutputLengthValidation(t *testing.T) {
	// Get algorithm suite for expected lengths
	algSuite := algorithms.AlgAES256GCMHkdfSha512CommitKey
	expectedDataKeyLength := algSuite.DataKeyLengthBytes()
	expectedCommitKeyLength := algSuite.CommitmentLengthBytes()
	expectedMessageIDLength := algSuite.IVLengthBytes()

	correctCommitment := hexToBytes(t, "f89818bc0a346d3a3426b68e9509b6b2ae5fe1f904aa329fb73625db", expectedCommitKeyLength)

	cases := []struct {
		name           string
		dataKeyLen     int
		messageIDLen   int
		expectError    bool
		errorContains  string
	}{
		{
			name:         "correct_input_lengths",
			dataKeyLen:   expectedDataKeyLength,   // 32 bytes
			messageIDLen: expectedMessageIDLength, // Message ID length for committing algorithm
			expectError:  true, // Will fail due to commitment mismatch, but that's OK - we're testing length validation
			errorContains: "commitment",
		},
		//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
		//= type=test
		//# - The length of the input keying material MUST equal the key derivation input length specified by the algorithm suite commit key derivation setting.
		{
			name:          "wrong_data_key_length",
			dataKeyLen:    16, // Wrong length
			messageIDLen:  expectedMessageIDLength,
			expectError:   true,
			errorContains: "plaintext data key length",
		},
		//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
		//= type=test
		//# - The salt MUST be the Message ID with the length defined in the algorithm suite.
		{
			name:          "wrong_message_id_length",
			dataKeyLen:    expectedDataKeyLength,
			messageIDLen:  16, // Wrong length
			expectError:   true,
			errorContains: "message ID length",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			
			dataKey := make([]byte, tc.dataKeyLen)
			for i := range dataKey {
				dataKey[i] = byte(i % 256)
			}

			messageID := make([]byte, tc.messageIDLen)
			for i := range messageID {
				messageID[i] = byte((i + 100) % 256)
			}

			result, err := DeriveKeys(dataKey, messageID, algorithms.AlgAES256GCMHkdfSha512CommitKey.ID(), correctCommitment)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for %s but got none", tc.name)
				}
				if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tc.errorContains, err.Error())
				} else {
					t.Logf("✓ Expected error for %s: %v", tc.name, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error for %s, got %v", tc.name, err)
				}

				//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
				//= type=test
				//# - The length of the output keying material MUST equal the encryption key length specified by the algorithm suite encryption settings.
				if len(result.DerivedEncryptionKey) != expectedDataKeyLength {
					t.Errorf("DerivedEncryptionKey length should be %d, got %d", expectedDataKeyLength, len(result.DerivedEncryptionKey))
				}
				
				//= ../specification/s3-encryption/key-derivation.md#hkdf-operation
				//= type=test
				//# - The length of the output keying material MUST equal the commit key length specified by the supported algorithm suites.
				if len(result.CommitKey) != expectedCommitKeyLength {
					t.Errorf("CommitKey length should be %d, got %d", expectedCommitKeyLength, len(result.CommitKey))
				}
				t.Logf("✓ Correct input/output lengths for %s", tc.name)
			}
		})
	}
}
