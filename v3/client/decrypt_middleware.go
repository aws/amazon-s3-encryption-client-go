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
	"io"
	"mime"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func customS3Decoder(s string) (decoded string) {
	// Manually decode S3's non-standard "double encoding"
	// This function assumes that the string has already been decoded once.
	// TODO: maybe refactor that into this function too along with checking if MIME-encoded
	var sb strings.Builder

	skipNext := false
	tupleIndex := 0
	tupleSize := -1
	tupleBuf := []byte{}
	for i, b := range []byte(s) {
		r := rune(b)
		// Check if the rune (code point) is non-US-ASCII
		if r > 127 && !skipNext {
			// non-ASCII characters need special treatment
			// due to double-encoding.
			// we convert the rune to binary
			// go 1.23 has a fancier library for this?
			buf := []byte{s[i], s[i+1]}
			wrongRune := string(buf)
			// need to UTF-16 encode it
			encd := utf16.Encode([]rune(wrongRune))[0]
			skipNext = true
			if tupleIndex == 0 {
				if encd < 191 {
					tupleSize = 1
				} else if encd < 223 {
					tupleSize = 2
				} else if encd < 255 {
					tupleSize = 3
				} else {
					tupleSize = 4
				}
				tupleBuf = make([]byte, tupleSize)
			}
			tupleBuf[tupleIndex] = byte(encd)
			tupleIndex += 1
		} else if r > 127 && skipNext {
			// only skip once
			skipNext = false
		} else {
			// else just write it
			sb.WriteByte(b)
		}
		// write full pair buf happens on a skip frame
		if tupleIndex == tupleSize {
			// maybe use size
			actualRune, _ := utf8.DecodeRune(tupleBuf)
			sb.WriteRune(actualRune)
			tupleIndex = 0
			tupleSize = -1
		}
	}
	return sb.String()
}

func decodeRFC2047Word(s string) (word string, isEncoded bool, err error) {
	word, err = rfc2047Decoder.Decode(s)

	if err == nil {
		return word, true, nil
	}

	if _, ok := err.(charsetError); ok {
		return s, true, err
	}

	// Ignore invalid RFC 2047 encoded-word errors.
	return s, false, nil
}

var rfc2047Decoder = mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		return nil, charsetError(charset)
	},
}

type charsetError string

func (c charsetError) Error() string {
	//TODO implement me
	return fmt.Sprintf("charset not supported: %q", string(c))
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
	iv, err := objectMetadata.GetDecodedIV()
	matDesc, err := objectMetadata.GetMatDesc()
	// S3 server likes to fuck with unicode
	// un fuck it here
	decoder := new(mime.WordDecoder)
	decoded, err := decoder.DecodeHeader(matDesc)
	fmt.Println("decoded: " + decoded)
	// Convert string to slice of runes
	runes := []rune(decoded)
	// Iterate over runes and print their binary representation
	fmt.Println("runes:")
	for _, r := range runes {
		fmt.Printf("%c: %b\n", r, r)
	}
	fmt.Println("bytes:")
	for _, b := range []byte(decoded) {
		fmt.Printf("%c: %08b\n ", b, b)
	}
	decoded_c := customS3Decoder(decoded)
	//decoded, _, _ := decodeRFC2047Word(matDesc)

	decryptMaterialsRequest := materials.DecryptMaterialsRequest{
		cipherKey,
		iv,
		decoded_c,
		objectMetadata.KeyringAlg,
		objectMetadata.CEKAlg,
		objectMetadata.TagLen,
	}
	decryptMaterials, err := m.client.Options.CryptographicMaterialsManager.DecryptMaterials(ctx, decryptMaterialsRequest)
	if err != nil {
		return out, metadata, fmt.Errorf("error while decrypting materials: %w", err)
	}

	cipher, err := cekFunc(*decryptMaterials)
	cipher.DecryptContents(result.Body)
	reader, err := cipher.DecryptContents(result.Body)
	if err != nil {
		return out, metadata, err
	}

	result.Body = reader
	out.Result = result

	return out, metadata, err
}
