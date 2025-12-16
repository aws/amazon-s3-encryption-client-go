// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/amazon-s3-encryption-client-go/v3/internal"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v3/algorithms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// DefaultMinFileSize is used to check whether we want to write to a temp file
// or store the data in memory.
const DefaultMinFileSize = 1024 * 512 * 5

// DefaultBufferSize is the default buffer size for GetObject operations
// The S3EC MUST set the buffer size to a reasonable default for GetObject
const DefaultBufferSize = 1024 * 64 // 64KB default buffer size

// EncryptionContext is used to extract Encryption Context to use on a per-request basis
const EncryptionContext = "EncryptionContext"

// PutObjectAPIClient is a client that implements the PutObject operation
type PutObjectAPIClient interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func (m *encryptMiddleware) addEncryptAPIOptions(options *s3.Options) {
	options.APIOptions = append(options.APIOptions,
		m.addEncryptMiddleware,
	)
}

func (m *encryptMiddleware) addEncryptMiddleware(stack *middleware.Stack) error {
	return stack.Serialize.Add(m, middleware.Before)
}

const encryptMiddlewareID = "S3Encrypt"

type encryptMiddleware struct {
	ec *S3EncryptionClientV3
}

// ID returns the resolver identifier
func (m *encryptMiddleware) ID() string {
	return encryptMiddlewareID
}

// HandleSerialize replaces the request body with an encrypted version and saves the envelope using the save strategy
func (m *encryptMiddleware) HandleSerialize(
	ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler,
) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {

	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*s3.PutObjectInput)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	// TODO - customize errors?
	reqCopy, err := req.SetStream(input.Body)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	n, ok, err := reqCopy.StreamLength()
	if !ok || err != nil {
		return out, metadata, err
	}

	dst, err := internal.GetWriterStore(m.ec.Options.TempFolderPath, n >= m.ec.Options.MinFileSize)
	if err != nil {
		return out, metadata, err
	}

	ec := ctx.Value(EncryptionContext)
	if ec == nil {
		ec = map[string]string{}
	}
	var matDesc materials.MaterialDescription = ec.(map[string]string)

	cmm := m.ec.Options.CryptographicMaterialsManager
	cryptoMaterials, err := cmm.GetEncryptionMaterials(ctx, matDesc)
	if err != nil {
		return out, metadata, err
	}
	var cipher internal.ContentCipher

	//= ../specification/s3-encryption/encryption.md#content-encryption
	//# The S3EC MUST use the encryption algorithm configured during [client](./client.md) initialization.
	if m.ec.Options.EncryptionAlgorithmSuite == algorithms.AlgAES256GCMHkdfSha512CommitKey {
		return out, metadata, fmt.Errorf("algorithm suite ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY is not supported for encryption in S3EC V3")
	} else if m.ec.Options.EncryptionAlgorithmSuite == algorithms.AlgAES256GCMIV12Tag16NoKDF {
		cipher, err = internal.NewAESGCMContentCipher(*cryptoMaterials)
		if err != nil {
			return out, metadata, err
		}
	} else {
		// S3EC V4 only supports writing AES-GCM, with or without key commitment.
		// Any other algorithms are invalid for encryption.
		//= ../specification/s3-encryption/encryption.md#alg-aes-256-ctr-iv16-tag16-no-kdf
		//# Attempts to encrypt using AES-CTR MUST fail.
		//= ../specification/s3-encryption/encryption.md#alg-aes-256-ctr-hkdf-sha512-commit-key
		//# Attempts to encrypt using key committing AES-CTR MUST fail.
		return out, metadata, fmt.Errorf("invalid content encryption algorithm found in options: %s", cryptoMaterials.CEKAlgorithm)
	}

	//= ../specification/s3-encryption/encryption.md#content-encryption
	//# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
	if n >= m.ec.Options.EncryptionAlgorithmSuite.CipherMaxContentLengthBytes() {
		return out, metadata, fmt.Errorf("plaintext length %d exceeds maximum content length for algorithm %s", n, cryptoMaterials.CEKAlgorithm)
	}

	stream := reqCopy.GetStream()
	lengthReader := internal.NewContentLengthReader(stream)
	reader, err := cipher.EncryptContents(lengthReader)
	if err != nil {
		return out, metadata, err
	}

	_, err = io.Copy(dst, reader)
	if err != nil {
		return out, metadata, err
	}

	data := cipher.GetCipherData()
	envelope, err := internal.EncodeMeta(lengthReader, data)
	if err != nil {
		return out, metadata, err
	}

	// rewind
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return out, metadata, err
	}

	// update the request body to encrypted contents
	input.Body = dst

	// save the metadata
	saveReq := &internal.SaveStrategyRequest{
		Envelope:    &envelope,
		HTTPRequest: req.Request,
		Input:       input,
	}

	// this saves the required crypto params (IV, tag length, etc.)
	strat := internal.ObjectMetadataSaveStrategy{}
	if err = strat.Save(ctx, saveReq); err != nil {
		return out, metadata, err
	}

	// update the middleware input's parameter which is what the generated serialize step will use
	in.Parameters = input

	out, metadata, err = next.HandleSerialize(ctx, in)

	// cleanup any temp files after the request is made
	dst.Cleanup()
	return out, metadata, err
}
