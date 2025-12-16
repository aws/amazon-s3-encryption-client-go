// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"strings"
	"testing"

	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
)

func TestNewAESGCMDecryptCommittingContentCipher_NilKeyCommitment_ReturnsError(t *testing.T) {
	// Given: materials with nil KeyCommitment
	materials := materials.CryptographicMaterials{
		KeyCommitment: nil,
	}

	// When: calling NewAESGCMDecryptCommittingContentCipher
	cipher, err := NewAESGCMDecryptCommittingContentCipher(materials)

	// Then: an error should be returned
	if err == nil {
		t.Fatal("expected error when KeyCommitment is nil, but got nil")
	}

	if cipher != nil {
		t.Fatal("expected cipher to be nil when error occurs, but got non-nil cipher")
	}

	// Verify the error message contains the expected text
	expectedErrorText := "key commitment is required for AES-GCM committing decryption"
	if !strings.Contains(err.Error(), expectedErrorText) {
		t.Fatalf("expected error message to contain '%s', but got: %s", expectedErrorText, err.Error())
	}
}
