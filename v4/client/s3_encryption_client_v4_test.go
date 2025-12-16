// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/amazon-s3-encryption-client-go/v4/algorithms"
	"github.com/aws/amazon-s3-encryption-client-go/v4/commitment"
	"github.com/aws/amazon-s3-encryption-client-go/v4/internal/awstesting"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

//= ../specification/s3-encryption/client.md#aws-sdk-compatibility
//= type=test
//# The S3EC SHOULD support invoking operations unrelated to client-side encryption e.g. CopyObject as the conventional AWS SDK S3 client would.
func TestWHEN_CallNonEncryptionOperationOnS3EC_THEN_PassthroughToPlaintextS3Client(t *testing.T) {
	// Create mock HTTP response for ListBuckets
	listBucketsResponse := `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>test-owner-id</ID>
        <DisplayName>test-owner</DisplayName>
    </Owner>
    <Buckets>
        <Bucket>
            <Name>test-bucket-1</Name>
            <CreationDate>2023-01-01T00:00:00.000Z</CreationDate>
        </Bucket>
        <Bucket>
            <Name>test-bucket-2</Name>
            <CreationDate>2023-01-02T00:00:00.000Z</CreationDate>
        </Bucket>
    </Buckets>
</ListAllMyBucketsResult>`

	// Create mock HTTP client
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			Status:     http.StatusText(200),
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(listBucketsResponse)),
		},
	}

	// Create test config with mock HTTP client
	tConfig := awstesting.Config()
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	// Create mock CMM
	mockCMM := &mockCMM{}

	// Create the S3 encryption client
	s3ec, err := New(s3Client, mockCMM)
	if err != nil {
		t.Fatalf("Failed to create S3 encryption client: %v", err)
	}

	// Test that ListBuckets is passed through to the underlying S3 client
	ctx := context.TODO()
	result, err := s3ec.ListBuckets(ctx, &s3.ListBucketsInput{})

	// Verify no error occurred
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify the response is parsed correctly
	if result == nil {
		t.Error("Expected non-nil result")
	} else {
		if len(result.Buckets) != 2 {
			t.Errorf("Expected 2 buckets, got %d", len(result.Buckets))
		}
		if result.Owner == nil || *result.Owner.DisplayName != "test-owner" {
			t.Error("Expected owner display name to be 'test-owner'")
		}
	}
}

//= ../specification/s3-encryption/client.md#aws-sdk-compatibility
//= type=test
//# The S3EC MUST adhere to the same interface for API operations as the conventional AWS SDK S3 client.
func TestS3EC_AdheresToSameInterfaceAsConventionalS3Client(t *testing.T) {
	// This test validates that S3EC and regular S3 client have identical interfaces
	// by calling both with the same parameters and verifying compatible behavior
	
	testCases := []struct {
		name        string
		operation   string
		setupMock   func() *awstesting.MockHttpClient
		testFunc    func(t *testing.T, s3Client *s3.Client, s3ec *S3EncryptionClientV4)
	}{
		{
			name:      "ListBuckets",
			operation: "ListBuckets",
			setupMock: func() *awstesting.MockHttpClient {
				mockResponse := `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>test-owner-id</ID>
        <DisplayName>test-owner</DisplayName>
    </Owner>
    <Buckets>
        <Bucket>
            <Name>test-bucket-1</Name>
            <CreationDate>2023-01-01T00:00:00.000Z</CreationDate>
        </Bucket>
        <Bucket>
            <Name>test-bucket-2</Name>
            <CreationDate>2023-01-02T00:00:00.000Z</CreationDate>
        </Bucket>
    </Buckets>
</ListAllMyBucketsResult>`
				return &awstesting.MockHttpClient{
					Response: &http.Response{
						Status:     http.StatusText(200),
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(mockResponse)),
					},
				}
			},
			testFunc: func(t *testing.T, s3Client *s3.Client, s3ec *S3EncryptionClientV4) {
				ctx := context.TODO()
				input := &s3.ListBucketsInput{}
				
				// Call both clients with identical parameters
				result1, err1 := s3Client.ListBuckets(ctx, input)
				result2, err2 := s3ec.ListBuckets(ctx, input)
				
				// Verify both calls succeed or fail in the same way
				if (err1 == nil) != (err2 == nil) {
					t.Errorf("Error behavior mismatch: s3Client error=%v, s3ec error=%v", err1, err2)
				}
				
				// If both succeed, verify output structure is compatible
				if err1 == nil && err2 == nil {
					if len(result1.Buckets) != len(result2.Buckets) {
						t.Errorf("Bucket count mismatch: s3Client=%d, s3ec=%d", len(result1.Buckets), len(result2.Buckets))
					}
					
					if result1.Owner != nil && result2.Owner != nil {
						if *result1.Owner.DisplayName != *result2.Owner.DisplayName {
							t.Errorf("Owner display name mismatch: s3Client=%s, s3ec=%s", 
								*result1.Owner.DisplayName, *result2.Owner.DisplayName)
						}
					}
					
					t.Logf("✓ ListBuckets: Both clients returned identical structured output")
				}
			},
		},
		{
			name:      "HeadBucket",
			operation: "HeadBucket",
			setupMock: func() *awstesting.MockHttpClient {
				return &awstesting.MockHttpClient{
					Response: &http.Response{
						Status:     http.StatusText(200),
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("")),
						Header: http.Header{
							"x-amz-bucket-region": []string{"us-east-1"},
						},
					},
				}
			},
			testFunc: func(t *testing.T, s3Client *s3.Client, s3ec *S3EncryptionClientV4) {
				ctx := context.TODO()
				input := &s3.HeadBucketInput{
					Bucket: aws.String("test-bucket"),
				}
				
				// Call both clients with identical parameters
				result1, err1 := s3Client.HeadBucket(ctx, input)
				result2, err2 := s3ec.HeadBucket(ctx, input)
				
				// Verify both calls succeed or fail in the same way
				if (err1 == nil) != (err2 == nil) {
					t.Errorf("Error behavior mismatch: s3Client error=%v, s3ec error=%v", err1, err2)
				}
				
				// If both succeed, verify output structure is compatible
				if err1 == nil && err2 == nil {
					// Both should return HeadBucketOutput with same structure
					// HeadBucketOutput doesn't have many fields, but both should be non-nil
					if result1 == nil || result2 == nil {
						t.Errorf("Result mismatch: s3Client result=%v, s3ec result=%v", result1, result2)
					}
					
					t.Logf("✓ HeadBucket: Both clients returned identical structured output")
				}
			},
		},
		{
			name:      "ListObjectsV2",
			operation: "ListObjectsV2",
			setupMock: func() *awstesting.MockHttpClient {
				mockResponse := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>test-bucket</Name>
    <Prefix></Prefix>
    <KeyCount>2</KeyCount>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>test-object-1</Key>
        <LastModified>2023-01-01T00:00:00.000Z</LastModified>
        <ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag>
        <Size>0</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
    <Contents>
        <Key>test-object-2</Key>
        <LastModified>2023-01-02T00:00:00.000Z</LastModified>
        <ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag>
        <Size>100</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
</ListBucketResult>`
				return &awstesting.MockHttpClient{
					Response: &http.Response{
						Status:     http.StatusText(200),
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(mockResponse)),
					},
				}
			},
			testFunc: func(t *testing.T, s3Client *s3.Client, s3ec *S3EncryptionClientV4) {
				ctx := context.TODO()
				input := &s3.ListObjectsV2Input{
					Bucket:  aws.String("test-bucket"),
					MaxKeys: 1000,
				}
				
				// Call both clients with identical parameters
				result1, err1 := s3Client.ListObjectsV2(ctx, input)
				result2, err2 := s3ec.ListObjectsV2(ctx, input)
				
				// Verify both calls succeed or fail in the same way
				if (err1 == nil) != (err2 == nil) {
					t.Errorf("Error behavior mismatch: s3Client error=%v, s3ec error=%v", err1, err2)
				}
				
				// If both succeed, verify output structure is compatible
				if err1 == nil && err2 == nil {
					if len(result1.Contents) != len(result2.Contents) {
						t.Errorf("Contents count mismatch: s3Client=%d, s3ec=%d", len(result1.Contents), len(result2.Contents))
					}
					
					if result1.KeyCount != result2.KeyCount {
						t.Errorf("KeyCount mismatch: s3Client=%d, s3ec=%d", result1.KeyCount, result2.KeyCount)
					}
					
					if *result1.Name != *result2.Name {
						t.Errorf("Bucket name mismatch: s3Client=%s, s3ec=%s", *result1.Name, *result2.Name)
					}
					
					t.Logf("✓ ListObjectsV2: Both clients returned identical structured output")
				}
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create two separate mock HTTP clients with identical responses
			mockClient1 := tc.setupMock()
			mockClient2 := tc.setupMock()
			
			// Create regular S3 client
			tConfig1 := awstesting.Config()
			tConfig1.HTTPClient = mockClient1
			s3Client := s3.NewFromConfig(tConfig1)
			
			// Create S3 encryption client
			tConfig2 := awstesting.Config()
			tConfig2.HTTPClient = mockClient2
			s3BaseClient := s3.NewFromConfig(tConfig2)
			
			mockCMM := &mockCMM{}
			s3ec, err := New(s3BaseClient, mockCMM)
			if err != nil {
				t.Fatalf("Failed to create S3 encryption client: %v", err)
			}
			
			// Run the specific test for this operation
			tc.testFunc(t, s3Client, s3ec)
			
			t.Logf("✓ %s: S3EC adheres to same interface as conventional S3 client", tc.operation)
		})
	}
}

// Custom mock HTTP client that can capture multiple requests
type multiRequestMockClient struct {
	capturedRequests []string
}

func (m *multiRequestMockClient) Do(req *http.Request) (*http.Response, error) {
	// Capture the request path to verify both object and instruction file are deleted
	m.capturedRequests = append(m.capturedRequests, req.URL.Path)
	
	return &http.Response{
		Status:     http.StatusText(204),
		StatusCode: http.StatusNoContent,
		Body:       io.NopCloser(strings.NewReader("")),
		Header: http.Header{
			"x-amz-delete-marker": []string{"false"},
		},
	}, nil
}

//= ../specification/s3-encryption/client.md#required-api-operations
//= type=test
//# - DeleteObject MUST delete the given object key.
//# - DeleteObject MUST delete the associated instruction file using the default instruction file suffix.
func TestS3EC_DeleteObject_DeletesObjectAndInstructionFile(t *testing.T) {
	// This test validates that DeleteObject deletes both the object and its instruction file
	// We'll use a custom mock to capture both delete requests
	
	// Create custom mock HTTP client that captures delete requests
	mockClient := &multiRequestMockClient{}

	// Create test config with mock HTTP client
	tConfig := awstesting.Config()
	tConfig.HTTPClient = mockClient
	s3Client := s3.NewFromConfig(tConfig)

	// Create mock CMM
	mockCMM := &mockCMM{}

	// Create the S3 encryption client
	s3ec, err := New(s3Client, mockCMM)
	if err != nil {
		t.Fatalf("Failed to create S3 encryption client: %v", err)
	}

	// Call DeleteObject - this should delete both object and instruction file
	ctx := context.TODO()
	result, err := s3ec.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
	})

	// Verify no error occurred
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify the response is not nil
	if result == nil {
		t.Error("Expected non-nil result from DeleteObject")
	}

	// Verify that both the object and instruction file delete requests were made
	if len(mockClient.capturedRequests) < 2 {
		t.Errorf("Expected at least 2 delete requests (object + instruction file), got %d", len(mockClient.capturedRequests))
	} else {
		// Check that requests include both the original object and the instruction file
		hasObjectDelete := false
		hasInstructionDelete := false
		
		for _, path := range mockClient.capturedRequests {
			if strings.Contains(path, "/test-key") && !strings.Contains(path, ".instruction") {
				hasObjectDelete = true
			}
			if strings.Contains(path, "/test-key.instruction") {
				hasInstructionDelete = true
			}
		}
		
		if !hasObjectDelete {
			t.Error("Expected delete request for original object 'test-key'")
		}
		if !hasInstructionDelete {
			t.Error("Expected delete request for instruction file 'test-key.instruction'")
		}
		
		t.Logf("✓ Verified DeleteObject deletes both object and instruction file")
	}
}
func TestS3ECInterfaceCompatibility(t *testing.T) {
	t.Run("ListBuckets", func(t *testing.T) {
		// Setup mock response
		mockResponse := `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Buckets><Bucket><Name>test-bucket</Name></Bucket></Buckets>
</ListAllMyBucketsResult>`

		// Create S3 client
		tConfig1 := awstesting.Config()
		tConfig1.HTTPClient = &awstesting.MockHttpClient{
			Response: &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(mockResponse))},
		}
		s3Client := s3.NewFromConfig(tConfig1)

		// Create S3EC
		tConfig2 := awstesting.Config()
		tConfig2.HTTPClient = &awstesting.MockHttpClient{
			Response: &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(mockResponse))},
		}
		s3ec, _ := New(s3.NewFromConfig(tConfig2), &mockCMM{})

		// Call same operation on both with same parameters
		ctx := context.TODO()
		input := &s3.ListBucketsInput{}
		
		result1, err1 := s3Client.ListBuckets(ctx, input)
		result2, err2 := s3ec.ListBuckets(ctx, input)

		// Verify same interface and output
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Error mismatch: s3Client=%v, s3ec=%v", err1, err2)
		}
		if len(result1.Buckets) != len(result2.Buckets) {
			t.Errorf("Output mismatch: s3Client buckets=%d, s3ec buckets=%d", len(result1.Buckets), len(result2.Buckets))
		}
	})

	t.Run("GetObject", func(t *testing.T) {
		// Verify interface compatibility - both should accept same input types
		ctx := context.TODO()
		input := &s3.GetObjectInput{
			Bucket: &[]string{"test-bucket"}[0],
			Key:    &[]string{"test-key"}[0],
		}
		
		// Test that both clients accept the same input parameters and return same types
		var result *s3.GetObjectOutput
		var err error
		
		// This verifies the interface is identical - same method signature
		// Don't assert equality; these clients behave differently. Important to assert the method signatures match.
		_ = func() {
			result, err = (&s3.Client{}).GetObject(ctx, input)
			result, err = (&S3EncryptionClientV4{}).GetObject(ctx, input)
		}
		
		// Suppress unused variable warnings
		_, _ = result, err
	})

	t.Run("PutObject", func(t *testing.T) {
		// Verify interface compatibility - both should accept same input types
		ctx := context.TODO()
		input := &s3.PutObjectInput{
			Bucket: &[]string{"test-bucket"}[0],
			Key:    &[]string{"test-key"}[0],
			Body:   strings.NewReader("test-content"),
		}
		
		// Test that both clients accept the same input parameters and return same types
		var result *s3.PutObjectOutput
		var err error
		
		// This verifies the interface is identical - same method signature
		// Don't assert equality; these clients behave differently. Important to assert the method signatures match.
		_ = func() {
			result, err = (&s3.Client{}).PutObject(ctx, input)
			result, err = (&S3EncryptionClientV4{}).PutObject(ctx, input)
		}
		
		// Suppress unused variable warnings
		_, _ = result, err
	})
}

//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
//= type=test
//# The option to enable legacy unauthenticated modes MUST be set to false by default.
func TestLegacyUnauthenticatedModes_DefaultDisabled(t *testing.T) {
	// Create test config
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	mockCMM := &mockCMM{}

	// Create S3EC without specifying EnableLegacyUnauthenticatedModes (should default to false)
	s3ec, err := New(s3Client, mockCMM)
	if err != nil {
		t.Fatalf("Failed to create S3 encryption client: %v", err)
	}

	// Verify that EnableLegacyUnauthenticatedModes defaults to false
	if s3ec.Options.EnableLegacyUnauthenticatedModes {
		t.Error("Expected EnableLegacyUnauthenticatedModes to default to false, but it was true")
	}

	t.Logf("✓ Verified EnableLegacyUnauthenticatedModes defaults to false")
}

//= ../specification/s3-encryption/client.md#wrapped-s3-client-s
//= type=test
//# The S3EC MUST support the option to provide an SDK S3 client instance during its initialization.
func TestS3EC_AcceptsProvidedS3ClientInstance(t *testing.T) {
	// Create a specific S3 client instance
	tConfig := awstesting.Config()
	providedS3Client := s3.NewFromConfig(tConfig)
	mockCMM := &mockCMM{}

	// Create S3EC with the provided S3 client
	s3ec, err := New(providedS3Client, mockCMM)
	if err != nil {
		t.Fatalf("Failed to create S3 encryption client: %v", err)
	}

	// Verify that the S3EC uses the provided client (they should be the same instance)
	if s3ec.Client != providedS3Client {
		t.Error("S3EC should use the provided S3 client instance")
	}

	t.Logf("✓ Verified S3EC accepts and uses provided S3 client instance")
}

//= ../specification/s3-encryption/client.md#encryption-algorithm
//= type=test
//# The S3EC MUST support configuration of the encryption algorithm (or algorithm suite) during its initialization.
func TestS3EC_SupportsEncryptionAlgorithmConfiguration(t *testing.T) {
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	mockCMM := &mockCMM{}

	// Test configuring different valid (non-legacy) algorithm suites
	testCases := []struct {
		name             string
		algorithm        *algorithms.AlgorithmSuite
		commitmentPolicy commitment.CommitmentPolicy
	}{
		{
			name:             "AES256GCMHkdfSha512CommitKey",
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey,
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT, // Committing algorithm
		},
		{
			name:             "AES256GCMIV12Tag16NoKDF",
			algorithm:        algorithms.AlgAES256GCMIV12Tag16NoKDF,
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT, // Non-committing algorithm
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Configure S3EC with specific encryption algorithm and appropriate commitment policy
			s3ec, err := New(s3Client, mockCMM, func(options *EncryptionClientOptions) {
				options.EncryptionAlgorithmSuite = tc.algorithm
				options.CommitmentPolicy = tc.commitmentPolicy
			})
			
			if err != nil {
				t.Fatalf("Failed to create S3EC with algorithm %s: %v", tc.name, err)
			}

			// Verify the algorithm was configured correctly
			if s3ec.Options.EncryptionAlgorithmSuite != tc.algorithm {
				t.Errorf("Expected algorithm %s, got %v", tc.name, s3ec.Options.EncryptionAlgorithmSuite)
			}

			// Verify the commitment policy was configured correctly
			if s3ec.Options.CommitmentPolicy != tc.commitmentPolicy {
				t.Errorf("Expected commitment policy %v, got %v", tc.commitmentPolicy, s3ec.Options.CommitmentPolicy)
			}

			t.Logf("✓ Successfully configured S3EC with algorithm: %s and commitment policy: %v", tc.name, tc.commitmentPolicy)
		})
	}
}

//= ../specification/s3-encryption/client.md#key-commitment
//= type=test
//# The S3EC MUST support configuration of the [Key Commitment policy](./key-commitment.md) during its initialization.
func TestS3EC_SupportsKeyCommitmentPolicyConfiguration(t *testing.T) {
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	mockCMM := &mockCMM{}

	// Test configuring all 3 commitment policies with compatible algorithms (happy path cases)
	testCases := []struct {
		name             string
		commitmentPolicy commitment.CommitmentPolicy
		algorithm        *algorithms.AlgorithmSuite
	}{
		{
			name:             "FORBID_ENCRYPT_ALLOW_DECRYPT",
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			algorithm:        algorithms.AlgAES256GCMIV12Tag16NoKDF, // Non-committing algorithm
		},
		{
			name:             "REQUIRE_ENCRYPT_ALLOW_DECRYPT",
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey, // Committing algorithm
		},
		{
			name:             "REQUIRE_ENCRYPT_REQUIRE_DECRYPT",
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey, // Committing algorithm
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Configure S3EC with specific commitment policy and compatible algorithm
			s3ec, err := New(s3Client, mockCMM, func(options *EncryptionClientOptions) {
				options.CommitmentPolicy = tc.commitmentPolicy
				options.EncryptionAlgorithmSuite = tc.algorithm
			})
			
			if err != nil {
				t.Fatalf("Failed to create S3EC with commitment policy %v: %v", tc.commitmentPolicy, err)
			}

			// Verify the commitment policy was configured correctly
			if s3ec.Options.CommitmentPolicy != tc.commitmentPolicy {
				t.Errorf("Expected commitment policy %v, got %v", tc.commitmentPolicy, s3ec.Options.CommitmentPolicy)
			}

			// Verify the algorithm was configured correctly
			if s3ec.Options.EncryptionAlgorithmSuite != tc.algorithm {
				t.Errorf("Expected algorithm %v, got %v", tc.algorithm, s3ec.Options.EncryptionAlgorithmSuite)
			}

			t.Logf("✓ Successfully configured S3EC with commitment policy: %v and algorithm: %v", tc.commitmentPolicy, tc.algorithm)
		})
	}
}

//= ../specification/s3-encryption/client.md#key-commitment
//= type=test
//# The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
//# If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
func TestS3EC_ValidatesAlgorithmCommitmentPolicyCompatibility(t *testing.T) {
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	mockCMM := &mockCMM{}

	// Test incompatible combinations that should fail
	incompatibleCases := []struct {
		name             string
		commitmentPolicy commitment.CommitmentPolicy
		algorithm        *algorithms.AlgorithmSuite
		expectedError    string
	}{
		{
			name:             "FORBID_ENCRYPT_ALLOW_DECRYPT with committing algorithm",
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			algorithm:        algorithms.AlgAES256GCMHkdfSha512CommitKey, // Committing
			expectedError:    "does not allow committing algorithm suites",
		},
		{
			name:             "REQUIRE_ENCRYPT_REQUIRE_DECRYPT with non-committing algorithm",
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			algorithm:        algorithms.AlgAES256GCMIV12Tag16NoKDF, // Non-committing
			expectedError:    "requires committing algorithm suites",
		},
	}

	for _, tc := range incompatibleCases {
		t.Run(tc.name, func(t *testing.T) {
			// Attempt to configure S3EC with incompatible commitment policy and algorithm - should fail
			_, err := New(s3Client, mockCMM, func(options *EncryptionClientOptions) {
				options.CommitmentPolicy = tc.commitmentPolicy
				options.EncryptionAlgorithmSuite = tc.algorithm
			})
			
			if err == nil {
				t.Errorf("Expected error for incompatible combination %s, but got none", tc.name)
			} else if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("Expected error containing '%s', got: %v", tc.expectedError, err)
			} else {
				t.Logf("✓ Correctly rejected incompatible combination %s: %v", tc.name, err)
			}
		})
	}
}

//= ../specification/s3-encryption/client.md#encryption-algorithm
//= type=test
//# The S3EC MUST validate that the configured encryption algorithm is not legacy.
//# If the configured encryption algorithm is legacy, then the S3EC MUST throw an exception.
func TestS3EC_RejectsLegacyEncryptionAlgorithms(t *testing.T) {
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	mockCMM := &mockCMM{}

	// Test that legacy algorithm suites are rejected
	legacyAlgorithms := []struct {
		name      string
		algorithm *algorithms.AlgorithmSuite
	}{
		{
			name:      "AES256CTRIV16Tag16NoKDF (legacy)",
			algorithm: algorithms.AlgAES256CTRIV16Tag16NoKDF,
		},
		{
			name:      "AES256CBCIV16NoKDF (legacy)",
			algorithm: algorithms.AlgAES256CBCIV16NoKDF,
		},
	}

	for _, tc := range legacyAlgorithms {
		t.Run(tc.name, func(t *testing.T) {
			// Attempt to configure S3EC with legacy encryption algorithm - should fail
			_, err := New(s3Client, mockCMM, func(options *EncryptionClientOptions) {
				options.EncryptionAlgorithmSuite = tc.algorithm
			})
			
			if err == nil {
				t.Errorf("Expected error when configuring legacy algorithm %s, but got none", tc.name)
			} else {
				t.Logf("✓ Correctly rejected legacy algorithm %s: %v", tc.name, err)
			}
		})
	}
}

func TestS3EC_BufferSizeConfiguration(t *testing.T) {
	tConfig := awstesting.Config()
	s3Client := s3.NewFromConfig(tConfig)
	mockCMM := &mockCMM{}

	//= ../specification/s3-encryption/client.md#set-buffer-size
	//= type=test
	//# If Delayed Authentication mode is disabled, and no buffer size is provided,
	//# the S3EC MUST set the buffer size to a reasonable default.
	t.Run("SetsReasonableDefaultBufferSize", func(t *testing.T) {
		// Create S3EC with default options
		s3ec, err := New(s3Client, mockCMM)
		if err != nil {
			t.Fatalf("Failed to create S3 encryption client: %v", err)
		}
		
		// Verify that the default buffer size is the default
		expectedBufferSize := int64(DefaultBufferSize)
		if s3ec.Options.BufferSize != expectedBufferSize {
			t.Errorf("Expected default buffer size to be %d, got %d", expectedBufferSize, s3ec.Options.BufferSize)
		}
		
		// Verify the default buffer size is the default
		if s3ec.Options.BufferSize != 64*1024 {
			t.Errorf("Expected default buffer size to be 64KB (65536 bytes), got %d", s3ec.Options.BufferSize)
		}
		
		t.Logf("✓ Verified S3EC sets reasonable default buffer size: %d bytes", s3ec.Options.BufferSize)
	})

	//= ../specification/s3-encryption/client.md#set-buffer-size
	//= type=test
	//# The S3EC SHOULD accept a configurable buffer size
	//# which refers to the maximum ciphertext length in bytes to store in memory
	//# when Delayed Authentication mode is disabled.
	t.Run("SupportsCustomBufferSizeConfiguration", func(t *testing.T) {
		// Test custom buffer size configuration
		customBufferSize := int64(128 * 1024) // 128KB
		
		s3ec, err := New(s3Client, mockCMM, func(options *EncryptionClientOptions) {
			options.BufferSize = customBufferSize
		})
		if err != nil {
			t.Fatalf("Failed to create S3 encryption client with custom buffer size: %v", err)
		}
		
		// Verify that the custom buffer size is set correctly
		if s3ec.Options.BufferSize != customBufferSize {
			t.Errorf("Expected buffer size to be %d, got %d", customBufferSize, s3ec.Options.BufferSize)
		}
		
		t.Logf("✓ Verified S3EC supports custom buffer size configuration: %d bytes", s3ec.Options.BufferSize)
	})
}
