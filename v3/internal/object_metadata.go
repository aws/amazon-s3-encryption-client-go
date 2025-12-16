// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v3/algorithms"
	"strconv"
)

// DefaultInstructionKeySuffix is appended to the end of the instruction file key when
// grabbing or saving to S3
const DefaultInstructionKeySuffix = ".instruction"

const (
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=implication
	//# The "x-amz-" prefix denotes that the metadata is owned by an Amazon product and MUST be prepended to all S3EC metadata mapkeys.
	amzPrefix 				   	   = "x-amz-"
	metaHeader                     = amzPrefix + "meta"
	keyV1Header                    = amzPrefix + "key"
	keyV2Header                    = amzPrefix + "key-v2"
	ivHeader                       = amzPrefix + "iv"
	matDescHeader                  = amzPrefix + "matdesc"
	CekAlgorithmHeader             = amzPrefix + "cek-alg"
	KeyringAlgorithmHeader         = amzPrefix + "wrap-alg"
	tagLengthHeader                = amzPrefix + "tag-len"
	unencryptedContentLengthHeader = amzPrefix + "unencrypted-content-length"

	// For the below constants, the specification comments describe the recommended constant names.
	// However, Go's JSON struct tags require literal string values and cannot reference constants.
	// This forces us to duplicate the string literals in the ObjectMetadata struct's `json:` tags.
	// While this creates duplication between these constants and the struct tags, it's a Go language
	// limitation - we cannot write `json:ContentCipherV3` in the struct definition.
	// There are tests that validate these constant values match the struct tags in ObjectMetadata.

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - This mapkey ("x-amz-c") SHOULD be represented by a constant named "CONTENT_CIPHER_V3" or similar in the implementation code.
	ContentCipherV3                = amzPrefix + "c"

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - This mapkey ("x-amz-3") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_V3" or similar in the implementation code.
	EncryptedDataKeyV3             = amzPrefix + "3"

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - This mapkey ("x-amz-m") SHOULD be represented by a constant named "MAT_DESC_V3" or similar in the implementation code.
	MatDescV3                      = amzPrefix + "m"

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - This mapkey ("x-amz-t") SHOULD be represented by a constant named "ENCRYPTION_CONTEXT_V3" or similar in the implementation code.
	EncryptionContextV3            = amzPrefix + "t"

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - This mapkey ("x-amz-w") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_ALGORITHM_V3" or similar in the implementation code.
	EncryptedDataKeyAlgorithmV3    = amzPrefix + "w"

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - This mapkey ("x-amz-d") SHOULD be represented by a constant named "KEY_COMMITMENT_V3" or similar in the implementation code.
	KeyCommitmentV3                = amzPrefix + "d"

	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - This mapkey ("x-amz-i") SHOULD be represented by a constant named "MESSAGE_ID_V3" or similar in the implementation code.
	MessageIDV3                    = amzPrefix + "i"
)

// S3EC Go V4 does not support reading nor writing V1 format metadata.

//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V1 format objects.

//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//# - The mapkey "x-amz-key" MUST be present for V1 format objects.

//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//# - The mapkey "x-amz-matdesc" MUST be present for V1 format objects.

//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=exception
//# - The mapkey "x-amz-iv" MUST be present for V1 format objects.

// ObjectMetadata encryption starts off by generating a random symmetric key using
// AES GCM. The SDK generates a random IV based off the encryption cipher
// chosen. The master key that was provided, whether by the user or KMS, will be used
// to encrypt the randomly generated symmetric key and base64 encode the iv. This will
// allow for decryption of that same data later.
//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=implication
//# The "x-amz-meta-" prefix is automatically added by the S3 server and MUST NOT be included in implementation code.
type ObjectMetadata struct {
	// IV is the randomly generated IV base64 encoded.
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
	IV string `json:"x-amz-iv"`
	// CipherKey is the randomly generated cipher key.
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
	CipherKey string `json:"x-amz-key-v2"`
	// MaterialDesc is a description to distinguish from other envelopes.
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
	MatDesc               string `json:"x-amz-matdesc"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
	KeyringAlg            string `json:"x-amz-wrap-alg"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
	CEKAlg                string `json:"x-amz-cek-alg"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
	TagLen                string `json:"x-amz-tag-len"`
	UnencryptedContentLen string `json:"x-amz-unencrypted-content-length"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-c" MUST be present for V3 format objects.
	ContentCipher string `json:"x-amz-c"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-3" MUST be present for V3 format objects.
	EncryptedDataKey string `json:"x-amz-3"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
	MatDescV3 string `json:"x-amz-m"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
	EncryptionContext string `json:"x-amz-t"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-w" MUST be present for V3 format objects.
	WrappingAlgorithm string `json:"x-amz-w"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-d" MUST be present for V3 format objects.
	KeyCommitment string `json:"x-amz-d"`
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//# - The mapkey "x-amz-i" MUST be present for V3 format objects.
	MessageID string `json:"x-amz-i"`
}

// V3 algorithm compression mappings
var (
	// Wrapping algorithm decompression: compressed value -> full algorithm name
	v3WrapAlgDecompression = map[string]string{
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval
		"02": "AES/GCM",
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval
		"12": "kms+context",
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval
		"22": "RSA-OAEP-SHA1",
	}
	
	// Wrapping algorithm compression: full algorithm name -> compressed value
	v3WrapAlgCompression = map[string]string{
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
		"AES/GCM": "02",
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
		"kms+context": "12",
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
		"RSA-OAEP-SHA1": "22",
	}
)

func (e *ObjectMetadata) GetDecodedKey() ([]byte, error) {
	var keyStr string
	if e.EncryptedDataKey != "" {
		// V3
		keyStr = e.EncryptedDataKey
	} else {
		// V2
		keyStr = e.CipherKey
	}
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (e *ObjectMetadata) GetDecodedMessageIDOrIV() ([]byte, error) {
	var value string
	if e.MessageID != "" {
		// V3
		value = e.MessageID
	} else {
		// V2
		value = e.IV
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func (e *ObjectMetadata) GetDecodedKeyCommitment() ([]byte, error) {
	// Only V3 has KeyCommitment
	commitment, err := base64.StdEncoding.DecodeString(e.KeyCommitment)
	if err != nil {
		return nil, err
	}
	return commitment, err
}

func (e *ObjectMetadata) GetMatDescV3() (string, error) {
	if e.MatDescV3 != "" {
		return e.MatDescV3, nil
	}
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//# If the mapkey x-amz-m is not present, the default Material Description value MUST be set to an empty map (`{}`).
	return "{}", nil
}

func (e *ObjectMetadata) GetEncryptionContextV3() (string, error) {
	// Only V3 has EncryptionContext
	if e.EncryptionContext != "" {
		return e.EncryptionContext, nil
	}
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//# If the mapkey x-amz-t is not present, the default Material Description value MUST be set to an empty map (`{}`).
	return "{}", nil
}

func (e *ObjectMetadata) GetMatDescV2() (string, error) {
	return e.MatDesc, nil
}

func (e *ObjectMetadata) GetEncryptionContextOrMatDescV3() (string, error) {
	wrappingAlg, err := e.GetFullWrappingAlgorithm()
	var matDesc string
	if wrappingAlg == "kms+context" {
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
		matDesc, err = e.GetEncryptionContextV3()
		return matDesc, err
	} else if wrappingAlg == "AES/GCM" || wrappingAlg == "RSA-OAEP-SHA1" {
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
		matDesc, err = e.GetMatDescV3()
		return matDesc, err
	}
	return "", fmt.Errorf("unsupported wrapping algorithm for getting Material Description: %s", wrappingAlg)
}

func (e *ObjectMetadata) GetContentEncryptionAlgorithmString() (string, error) {
	if e.ContentCipher != "" {
		// V3
		return e.ContentCipher, nil
	}
	if e.CEKAlg != "" {
		// V2
		return e.CEKAlg, nil
	}
	return "", fmt.Errorf("no content encryption algorithm found in metadata")
}

func (e *ObjectMetadata) GetContentEncryptionAlgorithmSuite() (*algorithms.AlgorithmSuite, error) {
	cekString, err := e.GetContentEncryptionAlgorithmString()
	if err != nil {
		return nil, err
	}
	if cekString == algorithms.AESGCMCommitKey {
		return algorithms.AlgAES256GCMHkdfSha512CommitKey, nil
	} else if cekString == algorithms.AESGCMNoPadding {
		return algorithms.AlgAES256GCMIV12Tag16NoKDF, nil
	} else if cekString == algorithms.AESCBCPKCS5 {
		return algorithms.AlgAES256CBCIV16NoKDF, nil
	} else if cekString == algorithms.AESCTRNoPadding {
		return algorithms.AlgAES256CTRIV16Tag16NoKDF, nil
	}
	return nil, fmt.Errorf("invalid content encryption algorithm found in metadata: %s", cekString)
}

func (e *ObjectMetadata) GetFullWrappingAlgorithm() (string, error) {
	if e.WrappingAlgorithm != "" {
		// V3
		// Decompress the V3 wrapping algorithm to its full name
		fullAlg, exists := v3WrapAlgDecompression[e.WrappingAlgorithm]
		if !exists {
			return "", fmt.Errorf("unknown V3 wrapping algorithm: %s", e.WrappingAlgorithm)
		}
		return fullAlg, nil
	}
	if e.KeyringAlg != "" {
		// V2
		return e.KeyringAlg, nil
	}
	return "", fmt.Errorf("no wrapping algorithm found in metadata")
}

// CompressWrappingAlgorithm compresses a full wrapping algorithm name to V3 format
func CompressWrappingAlgorithm(fullAlgorithm string) (string, error) {
	compressed, exists := v3WrapAlgCompression[fullAlgorithm]
	if !exists {
		return "", fmt.Errorf("unsupported wrapping algorithm for V3: %s", fullAlgorithm)
	}
	return compressed, nil
}

// UnmarshalJSON unmarshalls the given JSON bytes into ObjectMetadata
func (e *ObjectMetadata) UnmarshalJSON(value []byte) error {
	type StrictEnvelope ObjectMetadata
	type LaxEnvelope struct {
		StrictEnvelope
		TagLen                json.RawMessage `json:"x-amz-tag-len"`
		UnencryptedContentLen json.RawMessage `json:"x-amz-unencrypted-content-length"`
	}

	inner := LaxEnvelope{}
	err := json.Unmarshal(value, &inner)
	if err != nil {
		return err
	}
	*e = ObjectMetadata(inner.StrictEnvelope)

	e.TagLen, err = getJSONNumberAsString(inner.TagLen)
	if err != nil {
		return fmt.Errorf("failed to parse tag length: %w", err)
	}

	e.UnencryptedContentLen, err = getJSONNumberAsString(inner.UnencryptedContentLen)
	if err != nil {
		return fmt.Errorf("failed to parse unencrypted content length: %w", err)
	}

	return nil
}

// getJSONNumberAsString will attempt to convert the provided bytes into a string representation of a JSON Number.
// Only supports byte values that are string or integers, not floats. If the provided value is JSON Null, empty string
// will be returned.
func getJSONNumberAsString(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	// first try string, this also catches null value
	var s *string
	err := json.Unmarshal(data, &s)
	if err == nil && s != nil {
		return *s, nil
	} else if err == nil {
		return "", nil
	}

	// fallback to int64
	var i int64
	err = json.Unmarshal(data, &i)
	if err == nil {
		return strconv.FormatInt(i, 10), nil
	}

	return "", fmt.Errorf("failed to parse as JSON Number")
}

func EncodeMeta(reader lengthReader, cryptographicMaterials materials.CryptographicMaterials) (ObjectMetadata, error) {
	//= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
	//# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
	if cryptographicMaterials.CEKAlgorithm == algorithms.AESGCMCommitKey {
		return EncodeMetaV3(cryptographicMaterials)
	//= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
	//# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
	} else if cryptographicMaterials.CEKAlgorithm == algorithms.AESGCMNoPadding {
		return EncodeMetaV2(reader, cryptographicMaterials)
	} else {
		// Go S3EC V4 does not support writing other (ex. AES CBC) messages
		//= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
		//= type=exception
		//# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
		return ObjectMetadata{}, fmt.Errorf("unsupported CEK algorithm: %s", cryptographicMaterials.CEKAlgorithm)
	}
}

func EncodeMetaV2(reader lengthReader, cryptographicMaterials materials.CryptographicMaterials) (ObjectMetadata, error) {
	iv := base64.StdEncoding.EncodeToString(cryptographicMaterials.IV)
	key := base64.StdEncoding.EncodeToString(cryptographicMaterials.EncryptedKey)

	encodedMatDesc, err := cryptographicMaterials.MaterialDescription.EncodeDescription()
	if err != nil {
		return ObjectMetadata{}, err
	}

	contentLength := reader.GetContentLength()

	return ObjectMetadata{
		CipherKey:             key,
		IV:                    iv,
		MatDesc:               string(encodedMatDesc),
		KeyringAlg:            cryptographicMaterials.KeyringAlgorithm,
		CEKAlg:                cryptographicMaterials.CEKAlgorithm,
		TagLen:                cryptographicMaterials.TagLength,
		UnencryptedContentLen: strconv.FormatInt(contentLength, 10),
	}, nil
}

func EncodeMetaV3(cryptographicMaterials materials.CryptographicMaterials) (ObjectMetadata, error) {
	iv := base64.StdEncoding.EncodeToString(cryptographicMaterials.IV)
	key := base64.StdEncoding.EncodeToString(cryptographicMaterials.EncryptedKey)
	alg_suite := cryptographicMaterials.CEKAlgorithm
	wrapping_alg := cryptographicMaterials.KeyringAlgorithm
	commitment := base64.StdEncoding.EncodeToString(cryptographicMaterials.KeyCommitment)
	mat_desc_bytes, err := cryptographicMaterials.MaterialDescription.EncodeDescription()
	if err != nil {
		return ObjectMetadata{}, err
	}
	mat_desc := string(mat_desc_bytes)

	out := ObjectMetadata{
		EncryptedDataKey:  key,
		MessageID:         iv,
		ContentCipher:     alg_suite,
		WrappingAlgorithm: wrapping_alg,
		KeyCommitment:     commitment,
	}

	// Set MatDescV3 for AES/GCM or RSA-OAEP-SHA1, EncryptionContext for kms+context
	if wrapping_alg == "AES/GCM" || wrapping_alg == "RSA-OAEP-SHA1" {
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
		out.MatDescV3 = mat_desc
	} else if wrapping_alg == "kms+context" {
		//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
		//# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
		out.EncryptionContext = mat_desc
	}

	return out, nil
}

// MetadataFormat represents the format version of S3EC metadata
type MetadataFormat int

const (
	FormatUnknown MetadataFormat = iota
	FormatInstructionFile
	FormatV1
	FormatV2
	FormatV3
)

// Validate and detect correct metadata format 
func DetectAndValidateMetadataFormat(metadata map[string]string) (MetadataFormat, error) {
	// Check for mapkeys defined in the spec	
	hasV1Key := hasKey(metadata, keyV1Header) // "x-amz-key"
	hasV2Key := hasKey(metadata, keyV2Header) // "x-amz-key-v2"
	hasV3Key := hasKey(metadata, EncryptedDataKeyV3) // "x-amz-3"
	hasIv := hasKey(metadata, ivHeader) // "x-amz-iv"
	hasV3KeyCommitment := hasKey(metadata, KeyCommitmentV3) // "x-amz-d"
	hasV3KeyID := hasKey(metadata, MessageIDV3) // "x-amz-i"

	//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
	//# - If the metadata contains "x-amz-iv" and "x-amz-key" then the object MUST be considered as an S3EC-encrypted object using the V1 format.
	isV1 := hasIv && hasV1Key
	//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
	//# - If the metadata contains "x-amz-iv" and "x-amz-metadata-x-amz-key-v2" then the object MUST be considered as an S3EC-encrypted object using the V2 format.
	isV2 := hasIv && hasV2Key
	//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
	//# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
	isV3 := hasV3Key && hasV3KeyCommitment && hasV3KeyID

	//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
	//# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
	hasAtLeastOneV1ExclusiveKey := hasV1Key
	hasAtLeastOneV2ExclusiveKey := hasV2Key
	hasAtLeastOneV3ExclusiveKey := hasV3Key
	exclusiveKeyMatchCount := 0
	if hasAtLeastOneV1ExclusiveKey {
		exclusiveKeyMatchCount++
	}
	if hasAtLeastOneV2ExclusiveKey {
		exclusiveKeyMatchCount++
	}
	if hasAtLeastOneV3ExclusiveKey {
		exclusiveKeyMatchCount++
	}
	if exclusiveKeyMatchCount > 1 {
		return FormatUnknown, fmt.Errorf("metadata contains conflicting exclusive mapkeys")
	}

	versionMatchCount := 0
	if isV1 {
		versionMatchCount++
	}
	if isV2 {
		versionMatchCount++
	}
	if isV3 {
		versionMatchCount++
	}
	if versionMatchCount > 1 {
		return FormatUnknown, fmt.Errorf("metadata contains multiple S3EC format versions")
	}
	//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
	//# If the object matches none of the V1/V2/V3 formats, the S3EC MUST attempt to get the instruction file.
	if versionMatchCount == 0 {
		return FormatInstructionFile, nil
	}

	if isV1 {
		return FormatV1, nil
	}
	if isV2 {
		return FormatV2, nil
	}
	if isV3 {
		return FormatV3, nil
	}

	//= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
	//= type=implication
	//# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
	return FormatUnknown, fmt.Errorf("unable to determine metadata format")
}

// hasKey checks if a metadata key exists (with or without x-amz-meta prefix)
func hasKey(metadata map[string]string, key string) bool {
	// Check direct key
	if _, exists := metadata[key]; exists {
		return true
	}
	// Check with x-amz-meta prefix
	prefixedKey := metaHeader + "-" + key
	if _, exists := metadata[prefixedKey]; exists {
		return true
	}
	return false
}
