// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"crypto/rand"
	"fmt"
)

// GenerateNonZeroBytes generates random bytes and validates they are not all zeros
func GenerateNonZeroBytes(n int) ([]byte, error) {
	return GenerateNonZeroBytesWithGenerator(n, generateRandomBytes)
}

// GenerateNonZeroBytesWithGenerator allows injection of custom generator for testing
func GenerateNonZeroBytesWithGenerator(n int, generator func(int) ([]byte, error)) ([]byte, error) {
	const maxRetries = 3 // Prevent infinite loop in case of broken generator
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		//= ../specification/s3-encryption/encryption.md#content-encryption
		//# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
		keys_iv, err := generator(n)
		if err != nil {
			return nil, err
		}
		
		//= ../specification/s3-encryption/encryption.md#cipher-initialization
		//# The client SHOULD validate that the generated IV or Message ID is not zeros.
		allZero := true
		for _, b := range keys_iv {
			if b != 0 {
				allZero = false
				break
			}
		}
		
		// If not all zeros, we have a valid IV
		if !allZero {
			return keys_iv, nil
		}
		
		// If all zeros, retry (unless this is the last attempt)
	}
	
	// If we've exhausted all retries, return an error
	return nil, fmt.Errorf("failed to generate non-zero IV after %d attempts", maxRetries)
}

// Default generator using crypto/rand
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
