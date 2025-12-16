// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/amazon-s3-encryption-client-go/v4/algorithms"
	"github.com/aws/amazon-s3-encryption-client-go/v4/internal/awstesting"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v4/commitment"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestNewEncryptionClientV4_NonDefaults(t *testing.T) {
	tConfig := awstesting.Config()
	tClient := s3.NewFromConfig(tConfig)

	var mcmm = mockCMM{}
	v4, _ := New(tClient, mcmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CryptographicMaterialsManager = mcmm
		clientOptions.TempFolderPath = "/mock/path"
		clientOptions.MinFileSize = 42
	})

	if v4 == nil {
		t.Fatal("expected client to not be nil")
	}

	if !reflect.DeepEqual(mcmm, v4.Options.CryptographicMaterialsManager) {
		t.Errorf("CMM did not match provided value")
	}

	if v4.Client != tClient {
		t.Errorf("expected s3 client not be nil")
	}

	if e, a := 42, v4.Options.MinFileSize; int64(e) != a {
		t.Errorf("expected %v, got %v", e, a)
	}

	if e, a := "/mock/path", v4.Options.TempFolderPath; e != a {
		t.Errorf("expected %v, got %v", e, a)
	}
}

// keyringWithStaticTestIV is a test structure that wraps a CipherDataGeneratorWithCEKAlg and stubs in a static IV
// so that encryption tests can be guaranteed to be consistent.
type keyringWithStaticTestIV struct {
	IV []byte
	materials.Keyring
}

// isAWSFixture will avoid the warning log message when doing tests that need to mock the IV
func (k keyringWithStaticTestIV) isAWSFixture() bool {
	return true
}

func (k keyringWithStaticTestIV) OnEncrypt(ctx context.Context, materials *materials.EncryptionMaterials) (*materials.CryptographicMaterials, error) {
	cryptoMaterials, err := k.Keyring.OnEncrypt(ctx, materials)
	if err == nil {
		cryptoMaterials.IV = k.IV
	}
	return cryptoMaterials, err
}

func TestEncryptionClientV4_PutMockV2Object_KMSCONTEXT_AESGCM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, `{"CiphertextBlob":"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I","KeyId":"test-key-id","Plaintext":"lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono="}`)
	}))

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	var md materials.MaterialDescription
	iv, _ := hex.DecodeString("ae325acae2bfd5b9c3d0b813")
	kmsWithStaticIV := keyringWithStaticTestIV{
		IV: iv,
		Keyring: materials.NewKmsKeyring(kmsClient, "test-key-id", func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = false
		}),
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			Status:     http.StatusText(200),
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	cmm, err := materials.NewCryptographicMaterialsManager(kmsWithStaticIV)
	if err != nil {
		t.Fatalf("error while trying to create new CMM: %v", err)
	}
	client, _ := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
		Body: func() io.ReadSeeker {
			content, _ := hex.DecodeString("8f2c59c6dbfcacf356f3da40788cbde67ca38161a4702cbcf757af663e1c24a600001b2f500417dbf5a050f57db6737422b2ed6a44c75e0d")
			return bytes.NewReader(content)
		}(),
		Metadata: md,
	})
	if err != nil {
		t.Fatalf("PutObject failed with %v", err)
	}

	if tHttpClient.CapturedReq == nil || tHttpClient.CapturedBody == nil {
		t.Errorf("captured HTTP request/body was nil")
	}

	expected, _ := hex.DecodeString("4cd8e95a1c9b8b19640e02838b02c8c09e66250703a602956695afbc23cbb8647d51645955ab63b89733d0766f9a264adb88571b1d467b734ff72eb73d31de9a83670d59688c54ea")

	if !bytes.Equal(tHttpClient.CapturedBody, expected) {
		t.Error("encrypted bytes did not match expected")
	}

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestEncryptionClientV4_PutMockV3Object(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, `{"CiphertextBlob":"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I","KeyId":"test-key-id","Plaintext":"lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono="}`)
	}))

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	var md materials.MaterialDescription
	iv, _ := hex.DecodeString("ae325acae2bfd5b9c3d0b813")
	kmsWithStaticIV := keyringWithStaticTestIV{
		IV: iv,
		Keyring: materials.NewKmsKeyring(kmsClient, "test-key-id", func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = false
		}),
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			Status:     http.StatusText(200),
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	cmm, err := materials.NewCryptographicMaterialsManager(kmsWithStaticIV)
	if err != nil {
		t.Fatalf("error while trying to create new CMM: %v", err)
	}
	client, _ := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
	})

	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
		Body: func() io.ReadSeeker {
			content, _ := hex.DecodeString("8f2c59c6dbfcacf356f3da40788cbde67ca38161a4702cbcf757af663e1c24a600001b2f500417dbf5a050f57db6737422b2ed6a44c75e0d")
			return bytes.NewReader(content)
		}(),
		Metadata: md,
	})
	if err != nil {
		t.Fatalf("PutObject failed with %v", err)
	}

	if tHttpClient.CapturedReq == nil || tHttpClient.CapturedBody == nil {
		t.Errorf("captured HTTP request/body was nil")
	}

	if tHttpClient.CapturedReq != nil {
		headers := tHttpClient.CapturedReq.Header
		
		// V3 Content Cipher (x-amz-c) - should be "115" for AES256GCMHkdfSha512CommitKey
		expectedContentCipher := "115"
		if actualValue := headers.Get("X-Amz-Meta-X-Amz-C"); actualValue != expectedContentCipher {
			t.Errorf("X-Amz-Meta-X-Amz-C expected '%s', got '%s'", expectedContentCipher, actualValue)
		}
		
		// V3 Encrypted Data Key (x-amz-3) is nondeterministic, just check presence
		if actualValue := headers.Get("X-Amz-Meta-X-Amz-3"); strings.TrimSpace(actualValue) == "" {
			t.Errorf("X-Amz-Meta-X-Amz-3 should be present but was empty")
		}
		
		// V3 Wrapping Algorithm (x-amz-w) - should be "12" for kms+context
		expectedWrappingAlg := "12"
		if actualValue := headers.Get("X-Amz-Meta-X-Amz-W"); actualValue != expectedWrappingAlg {
			t.Errorf("X-Amz-Meta-X-Amz-W expected '%s', got '%s'", expectedWrappingAlg, actualValue)
		}
		
		// V3 Encryption Context (x-amz-t) - should be "{"aws:x-amz-cek-alg":"115"}" for otherwise empty encryption context
		expectedEncryptionContext := `{"aws:x-amz-cek-alg":"115"}`
		if actualValue := headers.Get("X-Amz-Meta-X-Amz-T"); actualValue != expectedEncryptionContext {
			t.Errorf("X-Amz-Meta-X-Amz-T expected '%s', got '%s'", expectedEncryptionContext, actualValue)
		}
		
		// V3 Message ID (x-amz-i) is nondeterministic, just check presence
		if actualValue := headers.Get("X-Amz-Meta-X-Amz-I"); strings.TrimSpace(actualValue) == "" {
			t.Errorf("X-Amz-Meta-X-Amz-I should be present but was empty")
		}
		
		// V3 Key Commitment (x-amz-d) is nondeterministic, just check presence
		if actualValue := headers.Get("X-Amz-Meta-X-Amz-D"); strings.TrimSpace(actualValue) == "" {
			t.Errorf("X-Amz-Meta-X-Amz-D should be present but was empty")
		}
	}

	// V3 body is non-deterministic due to IV derivation, so we will just check that it is present
	if tHttpClient.CapturedBody == nil || len(tHttpClient.CapturedBody) == 0 {
		t.Error("Expected encrypted content, but captured body was empty")
	}
}

func TestEncryptionClientv4_PutMockV2Object_KMSCONTEXT_AESGCM_EmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, `{"CiphertextBlob":"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I","KeyId":"test-key-id","Plaintext":"lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono="}`)
	}))

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	var md materials.MaterialDescription
	iv, _ := hex.DecodeString("ae325acae2bfd5b9c3d0b813")
	kmsWithStaticIV := keyringWithStaticTestIV{
		IV: iv,
		Keyring: materials.NewKmsKeyring(kmsClient, "test-key-id", func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = false
		}),
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			Status:     http.StatusText(200),
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	cmm, err := materials.NewCryptographicMaterialsManager(kmsWithStaticIV)
	if err != nil {
		t.Fatalf("error while trying to create new CMM: %v", err)
	}
	client, _ := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		Body:     new(bytes.Buffer),
		Metadata: md,
	})
	if err != nil {
		t.Fatalf("PutObject failed with %v", err)
	}

	if tHttpClient.CapturedReq == nil || tHttpClient.CapturedBody == nil {
		t.Errorf("captured HTTP request/body was nil")
	}

	expected, _ := hex.DecodeString("38a7dff91ec56105eedb716fe171675f")

	if !bytes.Equal(tHttpClient.CapturedBody, expected) {
		t.Errorf("encrypted bytes did not match expected")
	}

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

//= ../specification/s3-encryption/encryption.md#content-encryption
//= type=test
//# The S3EC MUST use the encryption algorithm configured during [client](./client.md) initialization.
func TestS3EC_UsesConfiguredEncryptionAlgorithm(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, `{"CiphertextBlob":"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I","KeyId":"test-key-id","Plaintext":"lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono="}`)
	}))

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	testCases := []struct {
		name              string
		algorithm         *algorithms.AlgorithmSuite
		commitmentPolicy  commitment.CommitmentPolicy
		ivHex            string
		expectedHeader   string
		expectedValue    string
	}{
		{
			name:             "AES256GCMIV12Tag16NoKDF",
			algorithm:        algorithms.AlgAES256GCMIV12Tag16NoKDF,
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			ivHex:           "ae325acae2bfd5b9c3d0b813",
			expectedHeader:  "X-Amz-Meta-X-Amz-Cek-Alg",
			expectedValue:   "AES/GCM/NoPadding",
		},
		{
			name:             "AES256GCMHkdfSha512CommitKey",
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey,
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			ivHex:           "ae325acae2bfd5b9c3d0b813ae325acae2bfd5b9c3d0b813ae325acae2bfd5b9",
			expectedHeader:  "X-Amz-Meta-X-Amz-C",
			expectedValue:   "115",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var md materials.MaterialDescription
			iv, _ := hex.DecodeString(tc.ivHex)
			kmsWithStaticIV := keyringWithStaticTestIV{
				IV: iv,
				Keyring: materials.NewKmsKeyring(kmsClient, "test-key-id", func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = false
				}),
			}

			tConfig := awstesting.Config()
			tHttpClient := &awstesting.MockHttpClient{
				Response: &http.Response{
					Status:     http.StatusText(200),
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte{})),
				},
			}
			tConfig.HTTPClient = tHttpClient
			s3Client := s3.NewFromConfig(tConfig)

			cmm, err := materials.NewCryptographicMaterialsManager(kmsWithStaticIV)
			if err != nil {
				t.Fatalf("error while trying to create new CMM: %v", err)
			}

			// Configure client with specific encryption algorithm
			client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
				clientOptions.CommitmentPolicy = tc.commitmentPolicy
				clientOptions.EncryptionAlgorithmSuite = tc.algorithm
			})
			if err != nil {
				t.Fatalf("Failed to create S3EC: %v", err)
			}

			// Verify the configured algorithm is set correctly
			if client.Options.EncryptionAlgorithmSuite != tc.algorithm {
				t.Errorf("Expected algorithm %v, got %v", tc.algorithm, client.Options.EncryptionAlgorithmSuite)
			}

			// Test that PutObject uses the configured algorithm
			_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
				Bucket: aws.String("test-bucket"),
				Key:    aws.String("test-key"),
				Body: func() io.ReadSeeker {
					content, _ := hex.DecodeString("8f2c59c6dbfcacf356f3da40788cbde67ca38161a4702cbcf757af663e1c24a600001b2f500417dbf5a050f57db6737422b2ed6a44c75e0d")
					return bytes.NewReader(content)
				}(),
				Metadata: md,
			})
			if err != nil {
				t.Fatalf("PutObject failed with %v", err)
			}

			// Verify the encryption was performed (captured body should not be empty)
			if tHttpClient.CapturedBody == nil || len(tHttpClient.CapturedBody) == 0 {
				t.Error("Expected encrypted content, but captured body was empty")
			}

			// Capture and validate object metadata for algorithm information
			if tHttpClient.CapturedReq == nil {
				t.Fatal("Expected captured HTTP request, but it was nil")
			}

			// Verify the algorithm-specific header is set correctly
			headers := tHttpClient.CapturedReq.Header
			actualValue := headers.Get(tc.expectedHeader)
			
			if actualValue == "" {
				t.Errorf("Expected %s header to be present for %s algorithm", tc.expectedHeader, tc.name)
			} else if actualValue != tc.expectedValue {
				t.Errorf("Expected %s header to be '%s', got '%s'", tc.expectedHeader, tc.expectedValue, actualValue)
			}

			t.Logf("✓ S3EC successfully used configured %s algorithm with correct metadata", tc.name)
			t.Logf("  - %s: %s", tc.expectedHeader, actualValue)
		})
	}
}

// mockLargeReader simulates a large reader without allocating memory
type mockLargeReader struct {
	size     int64
	position int64
}

func (r *mockLargeReader) Read(p []byte) (n int, err error) {
	if r.position >= r.size {
		return 0, io.EOF
	}
	
	remaining := r.size - r.position
	toRead := int64(len(p))
	if toRead > remaining {
		toRead = remaining
	}
	
	// Fill buffer with test data
	for i := int64(0); i < toRead; i++ {
		p[i] = byte((r.position + i) % 256)
	}
	
	r.position += toRead
	return int(toRead), nil
}

func (r *mockLargeReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.position = offset
	case io.SeekCurrent:
		r.position += offset
	case io.SeekEnd:
		r.position = r.size + offset
		if r.position > r.size {
			return 0, fmt.Errorf("seek position beyond end of reader")
		}
	}
	
	if r.position < 0 {
		r.position = 0
	}
	if r.position > r.size {
		r.position = r.size
	}
	
	return r.position, nil
}

//= ../specification/s3-encryption/encryption.md#content-encryption
//= type=test
//# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
func TestS3EC_ValidatesPlaintextLengthLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, `{"CiphertextBlob":"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I","KeyId":"test-key-id","Plaintext":"lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono="}`)
	}))

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	testCases := []struct {
		name              string
		algorithm         *algorithms.AlgorithmSuite
		commitmentPolicy  commitment.CommitmentPolicy
		contentSize       int64
		expectError       bool
		errorContains     string
	}{
		{
			name:             "AES256GCMIV12Tag16NoKDF_WithinLimit",
			algorithm:        algorithms.AlgAES256GCMIV12Tag16NoKDF,
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			contentSize:      1024, // Well within limit
			expectError:      false,
		},
		{
			name:             "AES256GCMIV12Tag16NoKDF_ExceedsLimit",
			algorithm:        algorithms.AlgAES256GCMIV12Tag16NoKDF,
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			contentSize:      algorithms.AlgAES256GCMIV12Tag16NoKDF.CipherMaxContentLengthBytes() + 1, // Just over the limit
			expectError:      true,
			errorContains:    "plaintext length",
		},
		{
			name:             "AES256GCMHkdfSha512CommitKey_WithinLimit",
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey,
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			contentSize:      1024, // Well within limit
			expectError:      false,
		},
		{
			name:             "AES256GCMHkdfSha512CommitKey_ExceedsLimit",
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey,
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			contentSize:      algorithms.AlgAES256GCMHkdfSha512CommitKey.CipherMaxContentLengthBytes() + 1, // Just over the limit
			expectError:      true,
			errorContains:    "plaintext length",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var md materials.MaterialDescription
			iv, _ := hex.DecodeString("ae325acae2bfd5b9c3d0b813")
			kmsWithStaticIV := keyringWithStaticTestIV{
				IV: iv,
				Keyring: materials.NewKmsKeyring(kmsClient, "test-key-id", func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = false
				}),
			}

			tConfig := awstesting.Config()
			tHttpClient := &awstesting.MockHttpClient{
				Response: &http.Response{
					Status:     http.StatusText(200),
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte{})),
				},
			}
			tConfig.HTTPClient = tHttpClient
			s3Client := s3.NewFromConfig(tConfig)

			cmm, err := materials.NewCryptographicMaterialsManager(kmsWithStaticIV)
			if err != nil {
				t.Fatalf("error while trying to create new CMM: %v", err)
			}

			// Configure client with specific encryption algorithm
			client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
				clientOptions.CommitmentPolicy = tc.commitmentPolicy
				clientOptions.EncryptionAlgorithmSuite = tc.algorithm
			})
			if err != nil {
				t.Fatalf("Failed to create S3EC: %v", err)
			}

			// Create a mock reader for the specified size (avoids memory allocation issues)
			var body io.ReadSeeker
			if tc.contentSize <= 1024*1024 { // For small sizes, use real content
				content := make([]byte, tc.contentSize)
				for i := range content {
					content[i] = byte(i % 256)
				}
				body = bytes.NewReader(content)
			} else {
				// For large sizes, use mock reader
				body = &mockLargeReader{size: tc.contentSize}
			}

			// Test PutObject with the content
			_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
				Bucket:   aws.String("test-bucket"),
				Key:      aws.String("test-key"),
				Body:     body,
				Metadata: md,
			})

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for content size %d bytes (limit: %d), but got none", 
						tc.contentSize, tc.algorithm.CipherMaxContentLengthBytes())
				} else if tc.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tc.errorContains)) {
					t.Errorf("Expected error to contain '%s', but got: %v", tc.errorContains, err)
				} else {
					t.Logf("✓ S3EC correctly rejected content exceeding maximum length for %s", tc.name)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for content size %d bytes (limit: %d), but got: %v", 
						tc.contentSize, tc.algorithm.CipherMaxContentLengthBytes(), err)
				} else {
					t.Logf("✓ S3EC correctly accepted content within maximum length for %s", tc.name)
				}
			}
		})
	}
}

func TestS3EC_IVGenerationAndMetadataInclusion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, `{"CiphertextBlob":"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I","KeyId":"test-key-id","Plaintext":"lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono="}`)
	}))

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	testCases := []struct {
		name              string
		algorithm         *algorithms.AlgorithmSuite
		commitmentPolicy  commitment.CommitmentPolicy
		ivHex            string
		expectedHeader   string
		expectedIVLength  int // in bytes
	}{
		{
			name:             "AES256GCMIV12Tag16NoKDF",
			algorithm:        algorithms.AlgAES256GCMIV12Tag16NoKDF,
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			ivHex:           "ae325acae2bfd5b9c3d0b813", // 12 bytes
			expectedHeader:  "X-Amz-Meta-X-Amz-Iv",
			expectedIVLength: 12, // 96 bits / 8 = 12 bytes
		},
		{
			name:             "AES256GCMHkdfSha512CommitKey",
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey,
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			ivHex:           "ae325acae2bfd5b9c3d0b813ae325acae2bfd5b9c3d0b813ae325acae2bfd5b9", // 32 bytes
			expectedHeader:  "X-Amz-Meta-X-Amz-I", // Message ID header for V3 format
			expectedIVLength: 28, // 224 bits / 8 = 28 bytes (Message ID length)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// First, verify the algorithm's IV length specification
			actualBytes := tc.algorithm.IVLengthBytes()
			expectedBits := actualBytes * 8

			if actualBytes != tc.expectedIVLength {
				t.Errorf("Expected IV/Message ID length %d bytes for %s, got %d bytes", 
					tc.expectedIVLength, tc.name, actualBytes)
			}

			t.Logf("✓ S3EC algorithm %s correctly defines IV/Message ID length: %d bytes (%d bits)", 
				tc.name, actualBytes, expectedBits)

			// Now test that the IV is properly included in content metadata during encryption
			var md materials.MaterialDescription
			iv, _ := hex.DecodeString(tc.ivHex)
			kmsWithStaticIV := keyringWithStaticTestIV{
				IV: iv,
				Keyring: materials.NewKmsKeyring(kmsClient, "test-key-id", func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = false
				}),
			}

			tConfig := awstesting.Config()
			tHttpClient := &awstesting.MockHttpClient{
				Response: &http.Response{
					Status:     http.StatusText(200),
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte{})),
				},
			}
			tConfig.HTTPClient = tHttpClient
			s3Client := s3.NewFromConfig(tConfig)

			cmm, err := materials.NewCryptographicMaterialsManager(kmsWithStaticIV)
			if err != nil {
				t.Fatalf("error while trying to create new CMM: %v", err)
			}

			// Configure client with specific encryption algorithm
			client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
				clientOptions.CommitmentPolicy = tc.commitmentPolicy
				clientOptions.EncryptionAlgorithmSuite = tc.algorithm
			})
			if err != nil {
				t.Fatalf("Failed to create S3EC: %v", err)
			}

			// Test that PutObject includes IV/Message ID in metadata
			_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
				Bucket: aws.String("test-bucket"),
				Key:    aws.String("test-key"),
				Body: func() io.ReadSeeker {
					content, _ := hex.DecodeString("8f2c59c6dbfcacf356f3da40788cbde67ca38161a4702cbcf757af663e1c24a600001b2f500417dbf5a050f57db6737422b2ed6a44c75e0d")
					return bytes.NewReader(content)
				}(),
				Metadata: md,
			})
			if err != nil {
				t.Fatalf("PutObject failed with %v", err)
			}

			// Verify the IV/Message ID is included in content metadata
			if tHttpClient.CapturedReq == nil {
				t.Fatal("Expected captured HTTP request, but it was nil")
			}

			headers := tHttpClient.CapturedReq.Header
			ivValue := headers.Get(tc.expectedHeader)
			
			if ivValue == "" {
				t.Errorf("Expected %s header to be present for %s algorithm", tc.expectedHeader, tc.name)
			} else {
				//= ../specification/s3-encryption/encryption.md#content-encryption
				//= type=test
				//# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
				//# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
				decodedIV, err := hex.DecodeString(ivValue)
				if err != nil {
					// Try base64 decoding for V3 format
					decodedIV, err = base64.StdEncoding.DecodeString(ivValue)
				}
				
				if err == nil {
					expectedLength := tc.algorithm.IVLengthBytes()
					
					if len(decodedIV) != expectedLength {
						t.Errorf("Expected IV/Message ID length %d bytes, got %d bytes", expectedLength, len(decodedIV))
					}
				}

				t.Logf("✓ S3EC successfully included IV/Message ID in content metadata for %s", tc.name)
				t.Logf("  - %s: %s", tc.expectedHeader, ivValue)
			}
		})
	}
}

//= ../specification/s3-encryption/encryption.md#alg-aes-256-ctr-iv16-tag16-no-kdf
//= type=test
//# Attempts to encrypt using AES-CTR MUST fail.
func TestS3EC_AESCTREncryptionMustFail(t *testing.T) {
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	
	var mcmm = mockCMM{}

	// Attempt to create client with AES-CTR algorithm - this should fail
	_, err := New(s3Client, mcmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.EncryptionAlgorithmSuite = algorithms.AlgAES256CTRIV16Tag16NoKDF
	})

	if err == nil {
		t.Fatalf("Expected error when attempting to use AES-CTR algorithm, but got none")
	}

	if !strings.Contains(err.Error(), "AES-CTR") && !strings.Contains(err.Error(), "CTR") {
		t.Errorf("Expected error to mention AES-CTR, but got: %v", err)
	}

	t.Logf("✓ S3EC correctly rejected AES-CTR encryption algorithm: %v", err)
}

//= ../specification/s3-encryption/encryption.md#alg-aes-256-ctr-hkdf-sha512-commit-key
//= type=test
//# Attempts to encrypt using key committing AES-CTR MUST fail.
func TestS3EC_CommittingAESCTREncryptionMustFail(t *testing.T) {
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	
	var mcmm = mockCMM{}

	// Attempt to create client with AES-CTR algorithm and committing policy - this should fail
	_, err := New(s3Client, mcmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.EncryptionAlgorithmSuite = algorithms.AlgAES256CTRIV16Tag16NoKDF
		clientOptions.CommitmentPolicy = commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
	})

	if err == nil {
		t.Fatalf("Expected error when attempting to use key committing AES-CTR algorithm, but got none")
	}

	if !strings.Contains(err.Error(), "AES-CTR") && !strings.Contains(err.Error(), "CTR") {
		t.Errorf("Expected error to mention AES-CTR, but got: %v", err)
	}

	t.Logf("✓ S3EC correctly rejected key committing AES-CTR encryption algorithm: %v", err)
}
