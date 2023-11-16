// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"github.com/aws/amazon-s3-encryption-client-go/materials"
	"io"
)

// ContentCipherBuilder is a builder interface that builds
// ciphers for each request.
type ContentCipherBuilder interface {
	ContentCipher() (ContentCipher, error)
}

// ContentCipherBuilderWithContext is a builder interface that builds
// ciphers for each request.
type ContentCipherBuilderWithContext interface {
	ContentCipherWithContext(context.Context) (ContentCipher, error)
}

// ContentCipher deals with encrypting and decrypting content
type ContentCipher interface {
	EncryptContents(io.Reader) (io.Reader, error)
	DecryptContents(io.ReadCloser) (io.ReadCloser, error)
	GetCipherData() materials.CryptographicMaterials
}

// CEKEntry is a builder that returns a proper content decrypter and error
type CEKEntry func(materials.CryptographicMaterials) (ContentCipher, error)
