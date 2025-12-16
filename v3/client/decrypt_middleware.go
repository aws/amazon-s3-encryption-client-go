// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"encoding/json"
	"github.com/aws/amazon-s3-encryption-client-go/v3/internal"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v3/algorithms"
	"github.com/aws/amazon-s3-encryption-client-go/v3/commitment"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"mime"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func customS3Decoder(matDesc string) (decoded string, e error) {
	// Manually decode S3's non-standard "double encoding"
	// First, mime decode it:
	decoder := new(mime.WordDecoder)
	s, err := decoder.DecodeHeader(matDesc)
	if err != nil {
		return "", fmt.Errorf("error while decoding material description: %s\n from S3 object metadata: %w", matDesc, err)
	}
	var sb strings.Builder

	skipNext := false
	var utf8buffer []byte
	// Iterate over the bytes in the string
	for i, b := range []byte(s) {
		r := rune(b)
		// Check if the rune (code point) is non-US-ASCII
		if r > 127 && !skipNext {
			// Non-ASCII characters need special treatment
			// due to double-encoding.
			// We are dealing with UTF-16 encoded codepoints
			// of the original UTF-8 characters.
			// So, take two bytes at a time...
			buf := []byte{s[i], s[i+1]}
			// Get the rune (code point)
			wrongRune := string(buf)
			// UTF-16 encode it
			encd := utf16.Encode([]rune(wrongRune))[0]
			// Buffer the byte-level representation of the code point
			// So that it can be UTF-8 encoded later
			utf8buffer = append(utf8buffer, byte(encd))
			skipNext = true
		} else if r > 127 && skipNext {
			// only skip once
			skipNext = false
		} else {
			// Decode the binary values as UTF-8
			// This recovers the original UTF-8
			for len(utf8buffer) > 0 {
				rb, size := utf8.DecodeRune(utf8buffer)
				sb.WriteRune(rb)
				utf8buffer = utf8buffer[size:]
			}
			sb.WriteByte(b)
		}
		// A more general solution would need to clear the utf8buffer here,
		// but specifically for material description,
		// we can assume that the string is JSON,
		// so the last character is '}' which is valid ASCII.
	}
	return sb.String(), nil
}

// GetObjectAPIClient is a client that implements the GetObject operation
type GetObjectAPIClient interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

func (m *decryptMiddleware) addDecryptAPIOptions(options *s3.Options) {
	options.APIOptions = append(options.APIOptions,
		m.addDecryptMiddleware,
	)
}

func (m *decryptMiddleware) addDecryptMiddleware(stack *middleware.Stack) error {
	return stack.Deserialize.Add(m, middleware.Before)
}

const decryptMiddlewareID = "S3Decrypt"

type decryptMiddleware struct {
	client *S3EncryptionClientV3
	input  *s3.GetObjectInput
}

// ID returns the resolver identifier
func (m *decryptMiddleware) ID() string {
	return decryptMiddlewareID
}

func (m *decryptMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	// call down the stack and get the deserialized result (decrypt middleware runs after the operation deserializer)
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	httpResp, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
	}

	result, ok := out.Result.(*s3.GetObjectOutput)
	if !ok {
		return out, metadata, fmt.Errorf("expected GetObjectOutput; got %v", out)
	}

	loadReq := &internal.LoadStrategyRequest{
		HTTPResponse: httpResp.Response,
		Input:        m.input,
	}

	// decode metadata
	loadStrat := internal.DefaultLoadStrategy{}
	objectMetadata, err := loadStrat.Load(ctx, loadReq)
	if err != nil {
		return out, metadata, fmt.Errorf("failed to load objectMetadata: bucket=%v; key=%v; err=%w", m.input.Bucket, m.input.Key, err)
	}

	// determine the content algorithm from metadata
	// this is purposefully done before attempting to
	// decrypt the materials
	var cekFunc internal.CEKEntry
	objectCekAlgSuite, err := objectMetadata.GetContentEncryptionAlgorithmSuite()
	if err != nil {
		return out, metadata, err
	}

	//= ../specification/s3-encryption/decryption.md#key-commitment
	//# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
	if err := ValidateContentEncryptionAlgorithmAgainstCommitmentPolicy(objectCekAlgSuite, m.client.Options.CommitmentPolicy); err != nil {
		return out, metadata, fmt.Errorf("object's content encryption algorithm is not valid for the selected commitment policy: %v, %w", objectCekAlgSuite, err)
	}

	var matDesc string
	if objectCekAlgSuite == algorithms.AlgAES256GCMHkdfSha512CommitKey {
		cekFunc = internal.NewAESGCMDecryptCommittingContentCipher
		matDesc, err = objectMetadata.GetEncryptionContextOrMatDescV3()
		if err != nil {
			return out, metadata, fmt.Errorf("error while getting material description for committing algorithm: %w", err)
		}
	} else if objectCekAlgSuite == algorithms.AlgAES256GCMIV12Tag16NoKDF {
		cekFunc = internal.NewAESGCMContentCipher
		matDesc, err = objectMetadata.GetMatDescV2()
		if err != nil {
			return out, metadata, fmt.Errorf("error while getting material description for AES/GCM algorithm: %w", err)
		}
	} else if objectCekAlgSuite == algorithms.AlgAES256CBCIV16NoKDF {
		if !m.client.Options.EnableLegacyUnauthenticatedModes {
			//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
			//# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
			//= ../specification/s3-encryption/decryption.md#legacy-decryption
			//# The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites unless specifically configured to do so.
			//= ../specification/s3-encryption/decryption.md#legacy-decryption
			//# If the S3EC is not configured to enable legacy unauthenticated content decryption, the client MUST throw an exception when attempting to decrypt an object encrypted with a legacy unauthenticated algorithm suite.
			return out, metadata, fmt.Errorf("configure client with enable legacy unauthenticated modes set to true to decrypt with %s", objectMetadata.CEKAlg)
		}
		//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
		//# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
		cekFunc = internal.NewAESCBCContentCipher
		matDesc, err = objectMetadata.GetMatDescV2()
		if err != nil {
			return out, metadata, fmt.Errorf("error while getting material description for AES/CBC algorithm: %w", err)
		}
	} else {
		return out, metadata, fmt.Errorf("invalid content encryption algorithm found in metadata: %s", objectMetadata.CEKAlg)
	}


	cipherKey, err := objectMetadata.GetDecodedKey()
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get decoded key for materials: %w", err)
	}
	iv, err := objectMetadata.GetDecodedMessageIDOrIV()
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get decoded IV for materials: %w", err)
	}
	keyringWrappingAlg, err := objectMetadata.GetFullWrappingAlgorithm()
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get wrapping algorithm for materials: %w", err)
	}

	// S3 server will encode metadata with non-US-ASCII characters
	// Decode it here to avoid parsing/decryption failure
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
	//# The S3EC SHOULD support decoding the S3 Server's "double encoding".
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
	//= type=exception
	//# If the S3EC does not support decoding the S3 Server's "double encoding" then it MUST return the content metadata untouched.
	//= ../specification/s3-encryption/data-format/content-metadata.md#v1-v2-shared
	//# This string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//# This material description string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//# This encryption context string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
	decodedMatDesc, err := customS3Decoder(matDesc)
	if err != nil {
		return out, metadata, fmt.Errorf("error while decoding Material Description: %w", err)
	}

	ec := ctx.Value(EncryptionContext)
	// If an encryption context is provided, the provided encryption context MUST match the encryption context stored in the metadata.
	if ec != nil {
		ecMap, ok := ec.(map[string]string)
		if !ok {
			return out, metadata, fmt.Errorf("encryption context provided to decrypt method is not valid JSON")
		}
		decodedMatDescMap := map[string]string{}
		if err := json.Unmarshal([]byte(decodedMatDesc), &decodedMatDescMap); err != nil {
			return out, metadata, fmt.Errorf("encryption context in stored object is not valid JSON: %w", err)
		}

		// The stored encryption context with the two reserved keys removed MUST match the provided encryption context.
		delete(decodedMatDescMap, "kms_cmk_id")
		delete(decodedMatDescMap, "aws:x-amz-cek-alg")

		if len(ecMap) != len(decodedMatDescMap) {
			return out, metadata, fmt.Errorf("Provided encryption context does not match information retrieved from S3")
		}
		for k, v := range ecMap {
			val, exists := decodedMatDescMap[k]
			if !exists || val != v {
				// If the stored encryption context with the two reserved keys removed does not match the provided encryption context, S3EC MUST throw an exception.
				return out, metadata, fmt.Errorf("Provided encryption context does not match information retrieved from S3")
			}
		}
	}

	cekAlg, err := objectMetadata.GetContentEncryptionAlgorithmString()
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get content encryption algorithm from metadata: %w", err)
	}

	decryptMaterialsRequest := materials.DecryptMaterialsRequest{
		cipherKey,
		iv,
		decodedMatDesc,
		keyringWrappingAlg,
		cekAlg,
		objectMetadata.TagLen,
	}
	decryptMaterials, err := m.client.Options.CryptographicMaterialsManager.DecryptMaterials(ctx, decryptMaterialsRequest)
	if err != nil {
		return out, metadata, fmt.Errorf("error while decrypting materials: %w", err)
	}

	// If the CMM did not provide a key commitment for a committing algorithm,
	// retrieve it from the object metadata.
	if (objectCekAlgSuite.IsCommitting() && decryptMaterials.KeyCommitment == nil) {
		commitment, err := objectMetadata.GetDecodedKeyCommitment()
		if err != nil {
			return out, metadata, fmt.Errorf("unable to get decoded key commitment for committing algorithm: %w", err)
		}
		decryptMaterials.KeyCommitment = commitment
	}

	cipher, err := cekFunc(*decryptMaterials)
	if err != nil {
		return out, metadata, err
	}
	reader, err := cipher.DecryptContents(result.Body)
	if err != nil {
		return out, metadata, err
	}

	// Apply buffer size configuration for GetObject operations
	// The S3EC MUST set the buffer size to a reasonable default for GetObject
	bufferedReader, err := internal.NewBufferedReader(reader, int(m.client.Options.BufferSize))
	if err != nil {
		return out, metadata, fmt.Errorf("unable to create buffered reader for decrypted contents: %w", err)
	}
	result.Body = bufferedReader
	out.Result = result

	return out, metadata, err
}

func ValidateContentEncryptionAlgorithmAgainstCommitmentPolicy(cekAlgSuite *algorithms.AlgorithmSuite, policy commitment.CommitmentPolicy) error {
	//= ../specification/s3-encryption/decryption.md#key-commitment
	//# If the commitment policy requires decryption using a committing algorithm suite,
	//# and the algorithm suite associated with the object does not support key commitment,
	//# then the S3EC MUST throw an exception.
	if policy.RequiresDecrypt() && !cekAlgSuite.IsCommitting() {
		return fmt.Errorf("commitment policy %v does not allow decryption using algorithm suite %v which does not support key commitment", policy, cekAlgSuite)
	}

	//= ../specification/s3-encryption/key-commitment.md#commitment-policy
	//# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT,
	//# the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
	if policy == commitment.FORBID_ENCRYPT_ALLOW_DECRYPT {
		if !cekAlgSuite.IsCommitting() {
			return nil
		}
	}

	//= ../specification/s3-encryption/key-commitment.md#commitment-policy
	//# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT,
	//# the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
	if policy == commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT {
		if !cekAlgSuite.IsCommitting() {
			return nil
		}
	}

	//= ../specification/s3-encryption/key-commitment.md#commitment-policy
	//# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
	//# the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
	if policy == commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT {
		if !cekAlgSuite.IsCommitting() {
			return fmt.Errorf("commitment policy %v does not allow decryption using algorithm suite %v which does not support key commitment", policy, cekAlgSuite)
		}
	}

	// If the policy is not recognized, return an error
	switch policy {
		case commitment.FORBID_ENCRYPT_ALLOW_DECRYPT, commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT, commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
			// do nothing -- valid policies
		default:
			return fmt.Errorf("unknown commitment policy: %v", policy)
	}

	return nil
}
