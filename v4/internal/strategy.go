// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/smithy-go"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// GetObjectAPIClient is a client that implements the GetObject operation
type GetObjectAPIClient interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// SaveStrategyRequest represents a request sent to a SaveStrategy to save the contents of an ObjectMetadata
type SaveStrategyRequest struct {
	// The envelope to save
	Envelope *ObjectMetadata

	// The HTTP request being built
	HTTPRequest *http.Request

	// The operation Input type
	Input interface{}
}

// ObjectMetadataSaveStrategy will save the metadata of the crypto contents to the header of
// the object.
type ObjectMetadataSaveStrategy struct{}

// Save will save the envelope to the request's header.
func (strat ObjectMetadataSaveStrategy) Save(ctx context.Context, saveReq *SaveStrategyRequest) error {

	input := saveReq.Input.(*s3.PutObjectInput)
	if input.Metadata == nil {
		input.Metadata = map[string]string{}
	}

	// S3EC Go V4 supports reading content metadata from an instruction file, but not writing it to an instruction file.
	// Any content metadata written is implicitly written to object metadata and not an instruction file.

	//= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
	//= type=implication
	//# By default, the S3EC MUST store content metadata in the S3 Object Metadata.
	//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
	//= type=implication
	//# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
	env := saveReq.Envelope
	if env.EncryptedDataKey != "" {
		// V3 format
		compressedAlg, err := CompressWrappingAlgorithm(env.WrappingAlgorithm)
		if err != nil {
			return fmt.Errorf("error while compressing wrapping algorithm: %w", err)
		}
		input.Metadata[http.CanonicalHeaderKey(ContentCipherV3)] = env.ContentCipher
		input.Metadata[http.CanonicalHeaderKey(EncryptedDataKeyV3)] = env.EncryptedDataKey
		input.Metadata[http.CanonicalHeaderKey(MatDescV3)] = env.MatDescV3
		input.Metadata[http.CanonicalHeaderKey(EncryptionContextV3)] = env.EncryptionContext
		input.Metadata[http.CanonicalHeaderKey(EncryptedDataKeyAlgorithmV3)] = compressedAlg
		input.Metadata[http.CanonicalHeaderKey(KeyCommitmentV3)] = env.KeyCommitment
		input.Metadata[http.CanonicalHeaderKey(MessageIDV3)] = env.MessageID
	} else {
		// V2 format
		input.Metadata[http.CanonicalHeaderKey(keyV2Header)] = env.CipherKey
		input.Metadata[http.CanonicalHeaderKey(ivHeader)] = env.IV
		input.Metadata[http.CanonicalHeaderKey(matDescHeader)] = env.MatDesc
		input.Metadata[http.CanonicalHeaderKey(KeyringAlgorithmHeader)] = env.KeyringAlg
		input.Metadata[http.CanonicalHeaderKey(CekAlgorithmHeader)] = env.CEKAlg
	}
	input.Metadata[http.CanonicalHeaderKey(unencryptedContentLengthHeader)] = env.UnencryptedContentLen

	if len(env.TagLen) > 0 {
		input.Metadata[http.CanonicalHeaderKey(tagLengthHeader)] = env.TagLen
	}
	return nil

	// S3EC Go V4 supports reading content metadata from an instruction file, but not writing it.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# The content metadata stored in the Instruction File MUST be serialized to a JSON string.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# The serialized JSON string MUST be the only contents of the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# Instruction File writes MUST NOT be enabled by default.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# Instruction File writes MUST be optionally configured during client creation or on each PutObject request.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# The S3EC MAY support re-encryption/key rotation via Instruction Files.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# The S3EC MUST NOT support providing a custom Instruction File suffix on ordinary writes; custom suffixes MUST only be used during re-encryption.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
	//= type=exception
	//# The S3EC SHOULD support providing a custom Instruction File suffix on GetObject requests, regardless of whether or not re-encryption is supported.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
	//= type=exception
	//# In the V1/V2 message format, all of the content metadata MUST be stored in the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST store the mapkey "x-amz-m" and its value (when present in the content metadata) in the Instruction File.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
	//= type=exception
	//# - The V3 message format MUST store the mapkey "x-amz-t" and its value (when present in the content metadata) in the Instruction File.
}

// LoadStrategyRequest represents a request sent to a LoadStrategy to load the contents of an ObjectMetadata
type LoadStrategyRequest struct {
	// The HTTP response
	HTTPResponse *http.Response

	// The operation Input type
	Input interface{}
}

// LoadStrategy ...
type LoadStrategy interface {
	Load(context.Context, *LoadStrategyRequest) (ObjectMetadata, error)
}

// S3LoadStrategy will load the instruction file from s3
type s3LoadStrategy struct {
	APIClient             GetObjectAPIClient
	InstructionFileSuffix string
}

// Load from a given instruction file suffix
func (load s3LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (ObjectMetadata, error) {
	env := ObjectMetadata{}
	if load.InstructionFileSuffix == "" {
		load.InstructionFileSuffix = DefaultInstructionKeySuffix
	}

	input := req.Input.(*s3.GetObjectInput)
	out, err := load.APIClient.GetObject(ctx, &s3.GetObjectInput{
		Key:    aws.String(strings.Join([]string{*input.Key, load.InstructionFileSuffix}, "")),
		Bucket: input.Bucket,
	})

	if err != nil {
		return env, err
	}

	b, err := io.ReadAll(out.Body)
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(b, &env)
	return env, err
}

// headerV2LoadStrategy will load the envelope from the metadata
type headerV2LoadStrategy struct{}

// Load from a given object's header
func (load headerV2LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (ObjectMetadata, error) {
	env := ObjectMetadata{}
	env.CipherKey = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, keyV2Header}, "-"))
	env.IV = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, ivHeader}, "-"))
	env.MatDesc = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, matDescHeader}, "-"))
	env.KeyringAlg = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, KeyringAlgorithmHeader}, "-"))
	env.CEKAlg = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, CekAlgorithmHeader}, "-"))
	env.TagLen = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, tagLengthHeader}, "-"))
	env.UnencryptedContentLen = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, unencryptedContentLengthHeader}, "-"))
	return env, nil
}

// headerV3LoadStrategy will load the V3 envelope from the metadata
type headerV3LoadStrategy struct{}

// Load from a given object's header using V3 format
func (load headerV3LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (ObjectMetadata, error) {
	v3Meta := ObjectMetadata{}
	v3Meta.ContentCipher = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, ContentCipherV3}, "-"))
	v3Meta.EncryptedDataKey = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, EncryptedDataKeyV3}, "-"))
	v3Meta.MatDescV3 = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, MatDescV3}, "-"))
	v3Meta.EncryptionContext = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, EncryptionContextV3}, "-"))
	v3Meta.WrappingAlgorithm = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, EncryptedDataKeyAlgorithmV3}, "-"))
	v3Meta.KeyCommitment = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, KeyCommitmentV3}, "-"))
	v3Meta.MessageID = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, MessageIDV3}, "-"))
	v3Meta.UnencryptedContentLen = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, unencryptedContentLengthHeader}, "-"))
	return v3Meta, nil
}

// DefaultLoadStrategy This is the only exported LoadStrategy since cx are no longer able to configure their client
// with a specific load strategy. Instead, we figure out which strategy to use based on the response header on decrypt.
type DefaultLoadStrategy struct {
	client GetObjectAPIClient
	suffix string
}

func (load DefaultLoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (ObjectMetadata, error) {
	// Create metadata map from headers for format detection
	metadata := make(map[string]string)
	for key, values := range req.HTTPResponse.Header {
		if len(values) > 0 {
			metadata[strings.ToLower(key)] = values[0]
		}
	}

	// Detect format and validate
	format, err := DetectAndValidateMetadataFormat(metadata)
	if err != nil {
		return ObjectMetadata{}, fmt.Errorf("invalid metadata format: %w", err)
	}

	switch format {
	case FormatV3:
		strat := headerV3LoadStrategy{}
		return strat.Load(ctx, req)
		
	case FormatV2:
		strat := headerV2LoadStrategy{}
		return strat.Load(ctx, req)
		
	case FormatV1:
		// In other S3EC implementations, decryption of v1 objects is supported.
		// Go, however, does not support this.
		return ObjectMetadata{}, &smithy.GenericAPIError{
			Code:    "V1NotSupportedError",
			Message: "The AWS SDK for Go does not support version 1",
		}
		
	default:
		// Fall back to instruction file loading
		var client GetObjectAPIClient
		if load.client == nil {
			cfg, err := config.LoadDefaultConfig(context.Background())
			if err != nil {
				return ObjectMetadata{}, fmt.Errorf("unable to create S3 client to load instruction file: %w", err)
			}
			client = s3.NewFromConfig(cfg)
		} else {
			client = load.client
		}

		// Load from instruction file
		strat := s3LoadStrategy{
			APIClient:             client,
			InstructionFileSuffix: load.suffix,
		}
		loadedMetadata, err := strat.Load(ctx, req)
		if err != nil {
			return ObjectMetadata{}, err
		}

		// For "V3 instruction file" format, load any additional metadata from headers
		// EncryptedDataKey is only present for V3 format (with or without instruction file)
		if loadedMetadata.EncryptedDataKey != "" {
			// If any values that should be in the headers were in the instruction file, raise error
			if loadedMetadata.ContentCipher != "" || loadedMetadata.KeyCommitment != "" || loadedMetadata.MessageID != "" {
				return ObjectMetadata{}, fmt.Errorf("invalid metadata format: missing V3 header values in instruction file format")
			}

			// Load these values from headers
			headerMeta, err := headerV3LoadStrategy{}.Load(ctx, req)
			if err != nil {
				return ObjectMetadata{}, err
			}
			loadedMetadata.ContentCipher = headerMeta.ContentCipher
			loadedMetadata.KeyCommitment = headerMeta.KeyCommitment
			loadedMetadata.MessageID = headerMeta.MessageID
		}
		
		return loadedMetadata, nil
	}
}
