// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v3/internal"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
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
	if objectMetadata.CEKAlg == internal.AESGCMNoPadding {
		cekFunc = internal.NewAESGCMContentCipher
	} else if strings.Contains(objectMetadata.CEKAlg, "AES/CBC") {
		if !m.client.Options.EnableLegacyUnauthenticatedModes {
			return out, metadata, fmt.Errorf("configure client with enable legacy unauthenticated modes set to true to decrypt with %s", objectMetadata.CEKAlg)
		}
		cekFunc = internal.NewAESCBCContentCipher
	} else {
		return out, metadata, fmt.Errorf("invalid content encryption algorithm found in metadata: %s", objectMetadata.CEKAlg)
	}

	cipherKey, err := objectMetadata.GetDecodedKey()
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get decoded key for materials: %w", err)
	}
	iv, err := objectMetadata.GetDecodedIV()
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get decoded IV for materials: %w", err)
	}
	matDesc, err := objectMetadata.GetMatDesc()
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get Material Description for materials: %w", err)
	}

	// S3 server will encode metadata with non-US-ASCII characters
	// Decode it here to avoid parsing/decryption failure
	decodedMatDesc, err := customS3Decoder(matDesc)
	if err != nil {
		return out, metadata, fmt.Errorf("error while decoding Material Description: %w", err)
	}

	decryptMaterialsRequest := materials.DecryptMaterialsRequest{
		cipherKey,
		iv,
		decodedMatDesc,
		objectMetadata.KeyringAlg,
		objectMetadata.CEKAlg,
		objectMetadata.TagLen,
	}
	decryptMaterials, err := m.client.Options.CryptographicMaterialsManager.DecryptMaterials(ctx, decryptMaterialsRequest)
	if err != nil {
		return out, metadata, fmt.Errorf("error while decrypting materials: %w", err)
	}

	cipher, err := cekFunc(*decryptMaterials)
	reader, err := cipher.DecryptContents(result.Body)
	if err != nil {
		return out, metadata, err
	}

	result.Body = reader
	out.Result = result

	return out, metadata, err
}
