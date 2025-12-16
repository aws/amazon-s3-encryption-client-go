// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"encoding/json"
	"reflect"
	"testing"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
)

func TestEnvelope_UnmarshalJSON(t *testing.T) {
	cases := map[string]struct {
		content  []byte
		expected ObjectMetadata
		actual   ObjectMetadata
	}{
		"string json numbers": {
			content: []byte(`{
  "x-amz-iv": "iv",
  "x-amz-key-v2": "key",
  "x-amz-matdesc": "{\"aws:x-amz-cek-alg\":\"AES/GCM/NoPadding\"}",
  "x-amz-wrap-alg": "kms+context",
  "x-amz-cek-alg": "AES/GCM/NoPadding",
  "x-amz-tag-len": "128",
  "x-amz-unencrypted-content-length": "1024"
}
`),
			expected: ObjectMetadata{
				IV:                    "iv",
				CipherKey:             "key",
				MatDesc:               `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"}`,
				KeyringAlg:            "kms+context",
				CEKAlg:                "AES/GCM/NoPadding",
				TagLen:                "128",
				UnencryptedContentLen: "1024",
			},
		},
		"integer json numbers": {
			content: []byte(`{
  "x-amz-iv": "iv",
  "x-amz-key-v2": "key",
  "x-amz-matdesc": "{\"aws:x-amz-cek-alg\":\"AES/GCM/NoPadding\"}",
  "x-amz-wrap-alg": "kms+context",
  "x-amz-cek-alg": "AES/GCM/NoPadding",
  "x-amz-tag-len": 128,
  "x-amz-unencrypted-content-length": 1024
}
`),
			expected: ObjectMetadata{
				IV:                    "iv",
				CipherKey:             "key",
				MatDesc:               `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"}`,
				KeyringAlg:            "kms+context",
				CEKAlg:                "AES/GCM/NoPadding",
				TagLen:                "128",
				UnencryptedContentLen: "1024",
			},
		},
		"null json numbers": {
			content: []byte(`{
  "x-amz-iv": "iv",
  "x-amz-key-v2": "key",
  "x-amz-matdesc": "{\"aws:x-amz-cek-alg\":\"AES/GCM/NoPadding\"}",
  "x-amz-wrap-alg": "kms+context",
  "x-amz-cek-alg": "AES/GCM/NoPadding",
  "x-amz-tag-len": null,
  "x-amz-unencrypted-content-length": null
}
`),
			expected: ObjectMetadata{
				IV:         "iv",
				CipherKey:  "key",
				MatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"}`,
				KeyringAlg: "kms+context",
				CEKAlg:     "AES/GCM/NoPadding",
			},
		},
		"no json numbers": {
			content: []byte(`{
  "x-amz-iv": "iv",
  "x-amz-key-v2": "key",
  "x-amz-matdesc": "{\"aws:x-amz-cek-alg\":\"AES/GCM/NoPadding\"}",
  "x-amz-wrap-alg": "kms+context",
  "x-amz-cek-alg": "AES/GCM/NoPadding"
}
`),
			expected: ObjectMetadata{
				IV:         "iv",
				CipherKey:  "key",
				MatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"}`,
				KeyringAlg: "kms+context",
				CEKAlg:     "AES/GCM/NoPadding",
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			err := json.Unmarshal(tt.content, &tt.actual)
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if !reflect.DeepEqual(tt.expected, tt.actual) {
				t.Errorf("expected %v, got %v", tt.expected, tt.actual)
			}
		})
	}
}

func TestObjectMetadata_UnmarshalJSON(t *testing.T) {
	cases := map[string]struct {
		content  []byte
		expected ObjectMetadata
		actual   ObjectMetadata
	}{
		"complete V3 metadata with encryption context": {
			content: []byte(`{
				"x-amz-c": "115",
				"x-amz-3": "dGVzdC1lbmNyeXB0ZWQta2V5",
				"x-amz-t": "{\"kms_cmk_id\":\"test-key-id\"}",
				"x-amz-w": "12",
				"x-amz-d": "dGVzdC1rZXktY29tbWl0bWVudA==",
				"x-amz-i": "dGVzdC1tZXNzYWdlLWlk"
				}
			`),
			expected: ObjectMetadata{
				ContentCipher:     "115",
				EncryptedDataKey:  "dGVzdC1lbmNyeXB0ZWQta2V5",
				EncryptionContext: `{"kms_cmk_id":"test-key-id"}`,
				WrappingAlgorithm: "12",
				KeyCommitment:     "dGVzdC1rZXktY29tbWl0bWVudA==",
				MessageID:         "dGVzdC1tZXNzYWdlLWlk",
			},
		},
		"V3 metadata with material description": {
			content: []byte(`{
				"x-amz-c": "AES/GCM/NoPadding",
				"x-amz-3": "dGVzdC1lbmNyeXB0ZWQta2V5",
				"x-amz-m": "{\"test\":\"material-desc\"}",
				"x-amz-w": "01",
				"x-amz-d": "dGVzdC1rZXktY29tbWl0bWVudA==",
				"x-amz-i": "dGVzdC1tZXNzYWdlLWlk"
				}
			`),
			expected: ObjectMetadata{
				ContentCipher:     "AES/GCM/NoPadding",
				EncryptedDataKey:  "dGVzdC1lbmNyeXB0ZWQta2V5",
				MatDescV3:         `{"test":"material-desc"}`,
				WrappingAlgorithm: "01",
				KeyCommitment:     "dGVzdC1rZXktY29tbWl0bWVudA==",
				MessageID:         "dGVzdC1tZXNzYWdlLWlk",
			},
		},
		"minimal V3 metadata": {
			content: []byte(`{
				"x-amz-c": "AES/CBC/PKCS5Padding",
				"x-amz-3": "dGVzdC1lbmNyeXB0ZWQta2V5",
				"x-amz-w": "11",
				"x-amz-d": "dGVzdC1rZXktY29tbWl0bWVudA==",
				"x-amz-i": "dGVzdC1tZXNzYWdlLWlk"
				}
			`),
			expected: ObjectMetadata{
				ContentCipher:     "AES/CBC/PKCS5Padding",
				EncryptedDataKey:  "dGVzdC1lbmNyeXB0ZWQta2V5",
				WrappingAlgorithm: "11",
				KeyCommitment:     "dGVzdC1rZXktY29tbWl0bWVudA==",
				MessageID:         "dGVzdC1tZXNzYWdlLWlk",
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			err := json.Unmarshal(tt.content, &tt.actual)
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if !reflect.DeepEqual(tt.expected, tt.actual) {
				t.Errorf("expected %v, got %v", tt.expected, tt.actual)
			}
		})
	}
}

func TestWrappingAlgorithmCompression(t *testing.T) {
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
	result, err := CompressWrappingAlgorithm("AES/GCM")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "02" {
		t.Errorf("expected 02, got %s", result)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
	result, err = CompressWrappingAlgorithm("kms+context")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "12" {
		t.Errorf("expected 12, got %s", result)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
	result, err = CompressWrappingAlgorithm("RSA-OAEP-SHA1")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "22" {
		t.Errorf("expected 22, got %s", result)
	}

	result, err = CompressWrappingAlgorithm("not-a-known-algorithm")
	if err == nil {
		t.Errorf("expected error but got none")
	}
}

func TestWrappingAlgorithmDecompression(t *testing.T) {
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval
	metadata := ObjectMetadata{WrappingAlgorithm: "02"}
	result, err := metadata.GetFullWrappingAlgorithm()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "AES/GCM" {
		t.Errorf("expected AES/GCM, got %s", result)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval
	metadata = ObjectMetadata{WrappingAlgorithm: "12"}
	result, err = metadata.GetFullWrappingAlgorithm()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "kms+context" {
		t.Errorf("expected kms+context, got %s", result)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval
	metadata = ObjectMetadata{WrappingAlgorithm: "22"}
	result, err = metadata.GetFullWrappingAlgorithm()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != "RSA-OAEP-SHA1" {
		t.Errorf("expected RSA-OAEP-SHA1, got %s", result)
	}

	metadata = ObjectMetadata{WrappingAlgorithm: "99"}
	result, err = metadata.GetFullWrappingAlgorithm()
	if err == nil {
		t.Errorf("expected error but got none")
	}
}

func TestDetectAndValidateMetadataFormat(t *testing.T) {
	cases := map[string]struct {
		metadata map[string]string
		expected MetadataFormat
	}{
		//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
		//= type=test
		//# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
		"V3 format": {
			metadata: map[string]string{
				"x-amz-3": "encrypted-key",
				"x-amz-d": "key-commitment",
				"x-amz-i": "message-id",
			},
			expected: FormatV3,
		},
		"V3 format with meta prefix": {
			metadata: map[string]string{
				"x-amz-meta-x-amz-3": "encrypted-key",
				"x-amz-meta-x-amz-d": "key-commitment",
				"x-amz-meta-x-amz-i": "message-id",
			},
			expected: FormatV3,
		},
		//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
		//= type=test
		//# - If the metadata contains "x-amz-iv" and "x-amz-metadata-x-amz-key-v2" then the object MUST be considered as an S3EC-encrypted object using the V2 format.
		"V2 format minimal meta prefix": {
			metadata: map[string]string{
				"x-amz-iv":      "iv",
				"x-amz-meta-x-amz-key-v2":  "key",
			},
			expected: FormatV2,
		},
		"V2 format minimal": {
			metadata: map[string]string{
				"x-amz-iv":      "iv",
				"x-amz-key-v2":  "key",
			},
			expected: FormatV2,
		},
		"V2 format": {
			metadata: map[string]string{
				"x-amz-iv":      "iv",
				"x-amz-key-v2":  "key",
				"x-amz-matdesc": "matdesc",
			},
			expected: FormatV2,
		},
		//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
		//= type=test
		//# - If the metadata contains "x-amz-iv" and "x-amz-key" then the object MUST be considered as an S3EC-encrypted object using the V1 format.
		"V1 format minimal": {
			metadata: map[string]string{
				"x-amz-iv":      "iv",
				"x-amz-key":     "key",
			},
			expected: FormatV1,
		},
		"V1 format": {
			metadata: map[string]string{
				"x-amz-iv":      "iv",
				"x-amz-key":     "key",
				"x-amz-matdesc": "matdesc",
			},
			expected: FormatV1,
		},
		//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
		//= type=test
		//# If the object matches none of the V1/V2/V3 formats, the S3EC MUST attempt to get the instruction file.
		"matching no format some keys": {
			metadata: map[string]string{
				"x-amz-abcdef": "not-a-key",
				"x-amz-123": "still-not-a-key",
			},
			expected: FormatInstructionFile,
		},
		"matching no format no keys": {
			metadata: map[string]string{},
			expected: FormatInstructionFile,
		},
		//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
		//= type=test
		//# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
		"multiple exclusive mapkeys case 1": {
			metadata: map[string]string{
				"x-amz-key": "key",
				"x-amz-key-v2": "key-v2",
				"x-amx-3": "key-v3",
			},
			expected: FormatUnknown,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := DetectAndValidateMetadataFormat(tt.metadata)
			if err != nil && result != FormatUnknown {
				t.Errorf("expected no error, got %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestObjectMetadataConstValues(t *testing.T) {
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=test
	//# - This mapkey ("x-amz-c") SHOULD be represented by a constant named "CONTENT_CIPHER_V3" or similar in the implementation code.
	if ContentCipherV3 != "x-amz-c" {
		t.Errorf("ContentCipherV3 MUST be `x-amz-c`, got %q", ContentCipherV3)
	}
	// Truly wild reflection usage in this test below to ensure the struct field in ObjectMetadata has the correct json tag to fully satisfy spec requirement
	field, ok := reflect.TypeOf(ObjectMetadata{}).FieldByName("ContentCipher")
	if !ok {
		t.Fatal("ObjectMetadata SHOULD have field ContentCipher")
	}
	if got := field.Tag.Get("json"); got != "x-amz-c" {
		t.Errorf("ContentCipher json tag MUST be `x-amz-c`, got %q", got)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=test
	//# - This mapkey ("x-amz-3") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_V3" or similar in the implementation code.
	if EncryptedDataKeyV3 != "x-amz-3" {
		t.Errorf("EncryptedDataKeyV3 MUST be `x-amz-3`, got %q", EncryptedDataKeyV3)
	}
	field, ok = reflect.TypeOf(ObjectMetadata{}).FieldByName("EncryptedDataKey")
	if !ok {
		t.Fatal("ObjectMetadata SHOULD have field EncryptedDataKey")
	}
	if got := field.Tag.Get("json"); got != "x-amz-3" {
		t.Errorf("EncryptedDataKey json tag MUST be `x-amz-3`, got %q", got)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=test
	//# - This mapkey ("x-amz-m") SHOULD be represented by a constant named "MAT_DESC_V3" or similar in the implementation code.
	if MatDescV3 != "x-amz-m" {
		t.Errorf("MatDescV3 MUST be `x-amz-m`, got %q", MatDescV3)
	}
	field, ok = reflect.TypeOf(ObjectMetadata{}).FieldByName("MatDescV3")
	if !ok {
		t.Fatal("ObjectMetadata SHOULD have field MatDesc")
	}
	if got := field.Tag.Get("json"); got != "x-amz-m" {
		t.Errorf("MatDesc json tag MUST be `x-amz-m`, got %q", got)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=test
	//# - This mapkey ("x-amz-t") SHOULD be represented by a constant named "ENCRYPTION_CONTEXT_V3" or similar in the implementation code.
	if EncryptionContextV3 != "x-amz-t" {
		t.Errorf("EncryptionContextV3 MUST be `x-amz-t`, got %q", EncryptionContextV3)
	}
	field, ok = reflect.TypeOf(ObjectMetadata{}).FieldByName("EncryptionContext")
	if !ok {
		t.Fatal("ObjectMetadata SHOULD have field EncryptionContext")
	}
	if got := field.Tag.Get("json"); got != "x-amz-t" {
		t.Errorf("EncryptionContext json tag MUST be `x-amz-t`, got %q", got)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=test
	//# - This mapkey ("x-amz-w") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_ALGORITHM_V3" or similar in the implementation code.
	if EncryptedDataKeyAlgorithmV3 != "x-amz-w" {
		t.Errorf("EncryptedDataKeyAlgorithmV3 MUST be `x-amz-w`, got %q", EncryptedDataKeyAlgorithmV3)
	}
	field, ok = reflect.TypeOf(ObjectMetadata{}).FieldByName("WrappingAlgorithm")
	if !ok {
		t.Fatal("ObjectMetadata SHOULD have field WrappingAlgorithm")
	}
	if got := field.Tag.Get("json"); got != "x-amz-w" {
		t.Errorf("WrappingAlgorithm json tag MUST be `x-amz-w`, got %q", got)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=test
	//# - This mapkey ("x-amz-d") SHOULD be represented by a constant named "KEY_COMMITMENT_V3" or similar in the implementation code.
	if KeyCommitmentV3 != "x-amz-d" {
		t.Errorf("KeyCommitmentV3 MUST be `x-amz-d`, got %q", KeyCommitmentV3)
	}
	field, ok = reflect.TypeOf(ObjectMetadata{}).FieldByName("KeyCommitment")
	if !ok {
		t.Fatal("ObjectMetadata SHOULD have field KeyCommitment")
	}
	if got := field.Tag.Get("json"); got != "x-amz-d" {
		t.Errorf("KeyCommitment json tag MUST be `x-amz-d`, got %q", got)
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=test
	//# - This mapkey ("x-amz-i") SHOULD be represented by a constant named "MESSAGE_ID_V3" or similar in the implementation code.
	if MessageIDV3 != "x-amz-i" {
		t.Errorf("MessageIDV3 MUST be `x-amz-i`, got %q", MessageIDV3)
	}
	field, ok = reflect.TypeOf(ObjectMetadata{}).FieldByName("MessageID")
	if !ok {
		t.Fatal("ObjectMetadata SHOULD have field MessageID")
	}
	if got := field.Tag.Get("json"); got != "x-amz-i" {
		t.Errorf("MessageID json tag MUST be `x-amz-i`, got %q", got)
	}
}

func TestMaterialDescriptionAndEncryptionContextRequirements(t *testing.T) {
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
	t.Run("Material Description used for AES/GCM", func(t *testing.T) {
		metadata := ObjectMetadata{
			WrappingAlgorithm: "02", // AES/GCM
			MatDescV3:         `{"test":"material-desc"}`,
		}
		result, err := metadata.GetEncryptionContextOrMatDescV3()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if result != `{"test":"material-desc"}` {
			t.Errorf("expected material description, got %s", result)
		}
	})

	t.Run("Material Description used for RSA-OAEP-SHA1", func(t *testing.T) {
		metadata := ObjectMetadata{
			WrappingAlgorithm: "22", // RSA-OAEP-SHA1
			MatDescV3:         `{"test":"rsa-material-desc"}`,
		}
		result, err := metadata.GetEncryptionContextOrMatDescV3()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if result != `{"test":"rsa-material-desc"}` {
			t.Errorf("expected material description, got %s", result)
		}
	})

	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# If the mapkey x-amz-m is not present, the default Material Description value MUST be set to an empty map (`{}`).
	t.Run("Default empty map when Material Description not present for AES/GCM", func(t *testing.T) {
		metadata := ObjectMetadata{
			WrappingAlgorithm: "02", // AES/GCM
			// MatDescV3 is empty
		}
		result, err := metadata.GetEncryptionContextOrMatDescV3()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if result != "{}" {
			t.Errorf("expected empty map {}, got %s", result)
		}
	})

	t.Run("Default empty map when Material Description not present for RSA-OAEP-SHA1", func(t *testing.T) {
		metadata := ObjectMetadata{
			WrappingAlgorithm: "22", // RSA-OAEP-SHA1
			// MatDescV3 is empty
		}
		result, err := metadata.GetEncryptionContextOrMatDescV3()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if result != "{}" {
			t.Errorf("expected empty map {}, got %s", result)
		}
	})

	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
	t.Run("Encryption Context used for kms+context", func(t *testing.T) {
		metadata := ObjectMetadata{
			WrappingAlgorithm: "12", // kms+context
			EncryptionContext: `{"kms_cmk_id":"test-key-id"}`,
		}
		result, err := metadata.GetEncryptionContextOrMatDescV3()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if result != `{"kms_cmk_id":"test-key-id"}` {
			t.Errorf("expected encryption context, got %s", result)
		}
	})

	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# If the mapkey x-amz-t is not present, the default Material Description value MUST be set to an empty map (`{}`).
	t.Run("Default empty map when Encryption Context not present for kms+context", func(t *testing.T) {
		metadata := ObjectMetadata{
			WrappingAlgorithm: "12", // kms+context
			// EncryptionContext is empty
		}
		result, err := metadata.GetEncryptionContextOrMatDescV3()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if result != "{}" {
			t.Errorf("expected empty map {}, got %s", result)
		}
	})
}

// mockLengthReader implements the lengthReader interface for testing
type mockLengthReader struct {
	contentLength int64
}

func (m *mockLengthReader) GetContentLength() int64 {
	return m.contentLength
}

func TestEncodeMetaV2(t *testing.T) {
	cases := map[string]struct {
		reader               lengthReader
		cryptographicMaterials materials.CryptographicMaterials
		expected             ObjectMetadata
	}{
		"standard V2 encoding": {
			reader: &mockLengthReader{contentLength: 1024},
			cryptographicMaterials: materials.CryptographicMaterials{
				Key:                 []byte("test-key-32-bytes-long-12345678"),
				IV:                  []byte("test-iv-12-b"),
				KeyringAlgorithm:    "kms+context",
				CEKAlgorithm:        "AES/GCM/NoPadding",
				TagLength:           "128",
				MaterialDescription: materials.MaterialDescription{"aws:x-amz-cek-alg": "AES/GCM/NoPadding", "custom": "value"},
				EncryptedKey:        []byte("encrypted-key-data"),
			},
			expected: ObjectMetadata{
				CipherKey:             "ZW5jcnlwdGVkLWtleS1kYXRh", // base64 of "encrypted-key-data"
				IV:                    "dGVzdC1pdi0xMi1i", // base64 of "test-iv-12-b"
				MatDesc:               `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","custom":"value"}`,
				KeyringAlg:            "kms+context",
				CEKAlg:                "AES/GCM/NoPadding",
				TagLen:                "128",
				UnencryptedContentLen: "1024",
			},
		},
		"V2 encoding with empty material description": {
			reader: &mockLengthReader{contentLength: 2048},
			cryptographicMaterials: materials.CryptographicMaterials{
				Key:                 []byte("test-key-32-bytes-long-12345678"),
				IV:                  []byte("test-iv-12-b"),
				KeyringAlgorithm:    "kms",
				CEKAlgorithm:        "AES/GCM/NoPadding",
				TagLength:           "96",
				MaterialDescription: materials.MaterialDescription{},
				EncryptedKey:        []byte("encrypted-key-data"),
			},
			expected: ObjectMetadata{
				CipherKey:             "ZW5jcnlwdGVkLWtleS1kYXRh", // base64 of "encrypted-key-data"
				IV:                    "dGVzdC1pdi0xMi1i", // base64 of "test-iv-12-b"
				MatDesc:               `{}`,
				KeyringAlg:            "kms",
				CEKAlg:                "AES/GCM/NoPadding",
				TagLen:                "96",
				UnencryptedContentLen: "2048",
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := EncodeMetaV2(tt.reader, tt.cryptographicMaterials)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

func TestEncodeMetaV3(t *testing.T) {
	cases := map[string]struct {
		cryptographicMaterials materials.CryptographicMaterials
		expected             ObjectMetadata
	}{
		"V3 encoding with AES/GCM wrapping algorithm": {
			cryptographicMaterials: materials.CryptographicMaterials{
				Key:                 []byte("test-key-32-bytes-long-12345678"),
				IV:                  []byte("test-iv-28-bytes-long-1234567890"),
				KeyringAlgorithm:    "AES/GCM",
				CEKAlgorithm:        "115",
				TagLength:           "128",
				MaterialDescription: materials.MaterialDescription{"test": "material-desc", "custom": "value"},
				EncryptedKey:        []byte("encrypted-key-data"),
				KeyCommitment:       []byte("key-commitment-data"),
			},
			expected: ObjectMetadata{
				EncryptedDataKey:  "ZW5jcnlwdGVkLWtleS1kYXRh", // base64 of "encrypted-key-data"
				MessageID:         "dGVzdC1pdi0yOC1ieXRlcy1sb25nLTEyMzQ1Njc4OTA=", // base64 of IV
				ContentCipher:     "115",
				WrappingAlgorithm: "AES/GCM",
				KeyCommitment:     "a2V5LWNvbW1pdG1lbnQtZGF0YQ==", // base64 of "key-commitment-data"
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
				MatDescV3:         `{"custom":"value","test":"material-desc"}`,
			},
		},
		"V3 encoding with kms+context wrapping algorithm": {
			cryptographicMaterials: materials.CryptographicMaterials{
				Key:                 []byte("test-key-32-bytes-long-12345678"),
				IV:                  []byte("test-iv-28-bytes-long-1234567890"),
				KeyringAlgorithm:    "kms+context",
				CEKAlgorithm:        "115",
				TagLength:           "128",
				MaterialDescription: materials.MaterialDescription{"kms_cmk_id": "test-key-id", "custom": "value"},
				EncryptedKey:        []byte("encrypted-key-data"),
				KeyCommitment:       []byte("key-commitment-data"),
			},
			expected: ObjectMetadata{
				EncryptedDataKey:  "ZW5jcnlwdGVkLWtleS1kYXRh", // base64 of "encrypted-key-data"
				MessageID:         "dGVzdC1pdi0yOC1ieXRlcy1sb25nLTEyMzQ1Njc4OTA=", // base64 of IV
				ContentCipher:     "115",
				WrappingAlgorithm: "kms+context",
				KeyCommitment:     "a2V5LWNvbW1pdG1lbnQtZGF0YQ==", // base64 of "key-commitment-data"
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
				EncryptionContext: `{"custom":"value","kms_cmk_id":"test-key-id"}`,
			},
		},
		"V3 encoding with RSA-OAEP-SHA1 wrapping algorithm": {
			cryptographicMaterials: materials.CryptographicMaterials{
				Key:                 []byte("test-key-32-bytes-long-12345678"),
				IV:                  []byte("test-iv-28-bytes-long-1234567890"),
				KeyringAlgorithm:    "RSA-OAEP-SHA1",
				CEKAlgorithm:        "115",
				TagLength:           "128",
				MaterialDescription: materials.MaterialDescription{"rsa": "material-desc"},
				EncryptedKey:        []byte("encrypted-key-data"),
				KeyCommitment:       []byte("key-commitment-data"),
			},
			expected: ObjectMetadata{
				EncryptedDataKey:  "ZW5jcnlwdGVkLWtleS1kYXRh", // base64 of "encrypted-key-data"
				MessageID:         "dGVzdC1pdi0yOC1ieXRlcy1sb25nLTEyMzQ1Njc4OTA=", // base64 of IV
				ContentCipher:     "115",
				WrappingAlgorithm: "RSA-OAEP-SHA1",
				KeyCommitment:     "a2V5LWNvbW1pdG1lbnQtZGF0YQ==", // base64 of "key-commitment-data"
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
				MatDescV3:         `{"rsa":"material-desc"}`,
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := EncodeMetaV3(tt.cryptographicMaterials)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}
