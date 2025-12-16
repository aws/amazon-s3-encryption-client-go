// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"log"
	"fmt"

	"github.com/aws/amazon-s3-encryption-client-go/v4/internal"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v4/algorithms"
	"github.com/aws/amazon-s3-encryption-client-go/v4/commitment"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3EncryptionClientV4 provides client-side encryption for S3.
// The client embeds a default client to provide support for control plane operations
// which do not involve encryption.
type S3EncryptionClientV4 struct {
	//= ../specification/s3-encryption/client.md#aws-sdk-compatibility
	//# The S3EC SHOULD support invoking operations unrelated to client-side encryption e.g. CopyObject as the conventional AWS SDK S3 client would.
	//= ../specification/s3-encryption/client.md#aws-sdk-compatibility
	//# The S3EC MUST adhere to the same interface for API operations as the conventional AWS SDK S3 client.

	*s3.Client                         // promoted anonymous field, it allows this type to call s3 Client methods
	Options    EncryptionClientOptions // options for encrypt/decrypt
}

//= ../specification/s3-encryption/client.md#aws-sdk-compatibility
//= type=implication
//# The S3EC MUST provide a different set of configuration options than the conventional S3 client.

// EncryptionClientOptions is the configuration options for the S3 Encryption Client.
type EncryptionClientOptions struct {
	// TempFolderPath is used to store temp files when calling PutObject
	// Temporary files are needed to compute the X-Amz-Content-Sha256 header
	TempFolderPath string

	// MinFileSize is the minimum size for the content to write to a
	// temporary file instead of using memory
	MinFileSize int64

	//= ../specification/s3-encryption/client.md#set-buffer-size
	//# The S3EC SHOULD accept a configurable buffer size
	//# which refers to the maximum ciphertext length in bytes to store in memory
	//# when Delayed Authentication mode is disabled.

	// BufferSize is the buffer size used for GetObject operations
	BufferSize int64

	// The logger to write logging messages to
	Logger *log.Logger

	// The CryptographicMaterialsManager to use to manage encryption and decryption materials
	CryptographicMaterialsManager materials.CryptographicMaterialsManager

	//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
	//= type=implication
	//# The S3EC MUST support the option to enable or disable legacy unauthenticated modes (content encryption algorithms).

	// EnableLegacyUnauthenticatedModes MUST be set to true in order to decrypt objects encrypted
	// using legacy (unauthenticated) modes such as AES/CBC. The default is false.
	EnableLegacyUnauthenticatedModes bool

	//= ../specification/s3-encryption/client.md#key-commitment
	//# The S3EC MUST support configuration of the [Key Commitment policy](./key-commitment.md) during its initialization.

	// CommitmentPolicy specifies the key commitment policy for this client.
	// S3EncryptionClientV4 defaults to commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT.
	// Objects written by a client configured with this default can be read by any v4 client
	// or any v3 client from v3.2.0 onward, but a client configured with this default can
	// only read objects written by other v4 clients configured with either
	// REQUIRE_ENCRYPT_ALLOW_DECRYPT or REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policies.
	// If an EncryptionAlgorithmSuite is also provided,
	// the selected CommitmentPolicy must also be compatible with the selected EncryptionAlgorithmSuite; if not, New() will return an error.
	CommitmentPolicy commitment.CommitmentPolicy

	//= ../specification/s3-encryption/client.md#encryption-algorithm
	//# The S3EC MUST support configuration of the encryption algorithm (or algorithm suite) during its initialization.

	// EncryptionAlgorithmSuite specifies the algorithm suite to use when encrypting objects.
	// If the commitment policy requires encrypting with key committing algorithms (default for S3EncryptionClientV4),
	// then S3EncryptionClientV4 defaults to algorithms.AlgAES256GCMHkdfSha512CommitKey.
	// However, If the commitment policy does not require encrypting with key committing algorithms,
	// S3EncryptionClientV4 defaults to algorithms.AlgAES256GCMIV12Tag16NoKDF.
	// The client will decrypt objects encrypted with any supported algorithm suite, provided that the
	// algorithms suite is compatible with the selected CommitmentPolicy and EnableLegacyUnauthenticatedModes options.
	// If a CommitmentPolicy is also provided,
	// the selected EncryptionAlgorithmSuite must also be compatible with the selected CommitmentPolicy; if not, New() will return an error.
	EncryptionAlgorithmSuite *algorithms.AlgorithmSuite
}

//# The S3EC MUST NOT support use of S3EC as the provided S3 client during its initialization; it MUST throw an exception in this case.

// New creates a new S3 Encryption Client v4 with the given CryptographicMaterialsManager
func New(s3Client *s3.Client, CryptographicMaterialsManager materials.CryptographicMaterialsManager, optFns ...func(options *EncryptionClientOptions)) (*S3EncryptionClientV4, error) {
	//= ../specification/s3-encryption/client.md#wrapped-s3-client-s
	//# The S3EC MUST support the option to provide an SDK S3 client instance during its initialization.
	// In Go, the requirement below is enforced/implied by the type system at compile time.
	// The New() function expects *s3.Client, but S3EncryptionClientV4 is a wholly different type.
	//= ../specification/s3-encryption/client.md#wrapped-s3-client-s
	//= type=implication
	//# The S3EC MUST NOT support use of S3EC as the provided S3 client during its initialization; it MUST throw an exception in this case.
	wrappedClient := s3Client
	// default options
	options := EncryptionClientOptions{
		MinFileSize:                      DefaultMinFileSize,
		//= ../specification/s3-encryption/client.md#set-buffer-size
		//# If Delayed Authentication mode is disabled, and no buffer size is provided,
		//# the S3EC MUST set the buffer size to a reasonable default.
		BufferSize:                       DefaultBufferSize,
		Logger:                           log.Default(),
		// S3EC Go V4 only accepts a CMM on client configuration, not a keyring.
		//= ../specification/s3-encryption/client.md#cryptographic-materials
		//= type=exception
		//# The S3EC MUST accept either one CMM or one Keyring instance upon initialization.
		//= ../specification/s3-encryption/client.md#cryptographic-materials
		//= type=exception
		//# If both a CMM and a Keyring are provided, the S3EC MUST throw an exception.
		//= ../specification/s3-encryption/client.md#cryptographic-materials
		//= type=exception
		//# When a Keyring is provided, the S3EC MUST create an instance of the DefaultCMM using the provided Keyring.
		//= ../specification/s3-encryption/client.md#cryptographic-materials
		//= type=exception
		//# The S3EC MAY accept key material directly.
		CryptographicMaterialsManager:    CryptographicMaterialsManager,
		//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
		//# The option to enable legacy unauthenticated modes MUST be set to false by default.
		EnableLegacyUnauthenticatedModes: false,
		CommitmentPolicy:                 commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,

		// S3EC Go V4 does not support delayed authentication mode.
		//= ../specification/s3-encryption/client.md#enable-delayed-authentication
		//= type=exception
		//# The S3EC MUST support the option to enable or disable Delayed Authentication mode.
		//= ../specification/s3-encryption/client.md#enable-delayed-authentication
		//= type=exception
		//# Delayed Authentication mode MUST be set to false by default.
		//= ../specification/s3-encryption/client.md#enable-delayed-authentication
		//= type=exception
		//# When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
		//= ../specification/s3-encryption/client.md#enable-delayed-authentication
		//= type=exception
		//# When disabled the S3EC MUST NOT release plaintext from a stream which has not been authenticated.
		//= ../specification/s3-encryption/client.md#set-buffer-size
		//= type=exception
		//# If Delayed Authentication mode is enabled, and the buffer size has been set to a value other than its default, the S3EC MUST throw an exception.
	
		// Go S3EC V4 does not support instruction file configuration.
		//= ../specification/s3-encryption/client.md#instruction-file-configuration
		//= type=exception
		//# The S3EC MAY support the option to provide Instruction File Configuration during its initialization.
		//= ../specification/s3-encryption/client.md#instruction-file-configuration
		//= type=exception
		//# If the S3EC in a given language supports Instruction Files, then it MUST accept Instruction File Configuration during its initialization.
		//= ../specification/s3-encryption/client.md#instruction-file-configuration
		//= type=exception
		//# In this case, the Instruction File Configuration SHOULD be optional, such that its default configuration is used when none is provided.

		// Go S3EC V4 does not support a single inherited configuration for underlying AWS SDK clients.
		//= ../specification/s3-encryption/client.md#inherited-sdk-configuration
		//= type=exception
		//# The S3EC MAY support directly configuring the wrapped SDK clients through its initialization.
		//= ../specification/s3-encryption/client.md#inherited-sdk-configuration
		//= type=exception
		//# For example, the S3EC MAY accept a credentials provider instance during its initialization.
		//= ../specification/s3-encryption/client.md#inherited-sdk-configuration
		//= type=exception
		//# If the S3EC accepts SDK client configuration, the configuration MUST be applied to all wrapped S3 clients.
		//= ../specification/s3-encryption/client.md#inherited-sdk-configuration
		//= type=exception
		//# If the S3EC accepts SDK client configuration, the configuration MUST be applied to all wrapped SDK clients including the KMS client.
	
		// Go S3EC V4 does not support supplying a custom source of randomness during client initialization.
		//= ../specification/s3-encryption/client.md#randomness
		//= type=exception
		//# The S3EC MAY accept a source of randomness during client initialization.
	}
	// apply functional options
	for _, fn := range optFns {
		fn(&options)
	}

	// If no algorithm suite, supply a default
	if options.EncryptionAlgorithmSuite == nil {
		options.EncryptionAlgorithmSuite = DefaultEncryptionAlgorithmSuite(options)
	}

	// Validate selected encryption algorithm suite
	if err := ValidateEncryptionAlgorithmSuite(options); err != nil {
		return nil, err
	}

	// use the given wrappedClient for the promoted anon fields
	s3ec := &S3EncryptionClientV4{wrappedClient, options}
	return s3ec, nil
}

func DefaultEncryptionAlgorithmSuite(options EncryptionClientOptions) *algorithms.AlgorithmSuite {
	if options.CommitmentPolicy.RequiresEncrypt() {
		return algorithms.AlgAES256GCMHkdfSha512CommitKey
	} else {
		return algorithms.AlgAES256GCMIV12Tag16NoKDF
	}
}

// Explict (but verbose) validations of S3EC specification
func ValidateEncryptionAlgorithmSuite(options EncryptionClientOptions) error {
	//= ../specification/s3-encryption/client.md#encryption-algorithm
	//# The S3EC MUST validate that the configured encryption algorithm is not legacy.
	//= ../specification/s3-encryption/client.md#encryption-algorithm
	//# If the configured encryption algorithm is legacy, then the S3EC MUST throw an exception.
	if options.EncryptionAlgorithmSuite.IsLegacy() {
		return fmt.Errorf("legacy algorithm suites are not allowed for decrypt, got %v", options.EncryptionAlgorithmSuite)
	}
	//= ../specification/s3-encryption/client.md#key-commitment
	//# The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
	//= ../specification/s3-encryption/client.md#key-commitment
	//# If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
	//= ../specification/s3-encryption/key-commitment.md#commitment-policy
	//# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
	if options.CommitmentPolicy == commitment.FORBID_ENCRYPT_ALLOW_DECRYPT {
		if options.EncryptionAlgorithmSuite.IsCommitting() {
			return fmt.Errorf("CommitmentPolicy FORBID_ENCRYPT_ALLOW_DECRYPT does not allow committing algorithm suites, got %v", options.EncryptionAlgorithmSuite)
		}
	//= ../specification/s3-encryption/key-commitment.md#commitment-policy
	//# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
	} else if options.CommitmentPolicy == commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT {
		if !options.EncryptionAlgorithmSuite.IsCommitting() {
			return fmt.Errorf("CommitmentPolicy REQUIRE_ENCRYPT_ALLOW_DECRYPT requires committing algorithm suites, got %v", options.EncryptionAlgorithmSuite)
		}
	//= ../specification/s3-encryption/key-commitment.md#commitment-policy
	//# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
	} else if options.CommitmentPolicy == commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT {
		if !options.EncryptionAlgorithmSuite.IsCommitting() {
			return fmt.Errorf("CommitmentPolicy REQUIRE_ENCRYPT_REQUIRE_DECRYPT requires committing algorithm suites, got %v", options.EncryptionAlgorithmSuite)
		}
	} else {
		return fmt.Errorf("unknown CommitmentPolicy %v", options.CommitmentPolicy)
	}
	return nil
}

//= ../specification/s3-encryption/client.md#required-api-operations
//# - GetObject MUST be implemented by the S3EC.
//= ../specification/s3-encryption/client.md#aws-sdk-compatibility
//# The S3EC MUST adhere to the same interface for API operations as the conventional AWS SDK S3 client.

// GetObject will make a request to s3 and retrieve the object. In this process
// decryption will be done. The SDK only supports region reads of KMS and GCM.
func (c *S3EncryptionClientV4) GetObject(ctx context.Context, input *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	// Go S3EC V4 does not support ranged gets.
	//= ../specification/s3-encryption/decryption.md#ranged-gets
	//= type=exception
	//# The S3EC MAY support the "range" parameter on GetObject which specifies a subset of bytes to download and decrypt.
	//= ../specification/s3-encryption/decryption.md#ranged-gets
	//= type=exception
	//# If the S3EC supports Ranged Gets, the S3EC MUST adjust the customer-provided range to include the beginning and end of the cipher blocks for the given range.
	//= ../specification/s3-encryption/decryption.md#ranged-gets
	//= type=exception
	//# For requests which provide a range to decrypt an object encrypted with an authenticated algorithm suite, the corresponding CTR-based algorithm suite is used.
	//= ../specification/s3-encryption/decryption.md#ranged-gets
	//= type=exception
	//# If the GetObject response contains a range, but the GetObject request does not contain a range, the S3EC MUST throw an exception.
	//= ../specification/s3-encryption/decryption.md#ranged-gets
	//= type=exception
	//# If the object was encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF, then ALG_AES_256_CTR_IV16_TAG16_NO_KDF MUST be used to decrypt the range of the object.
	//= ../specification/s3-encryption/decryption.md#ranged-gets
	//= type=exception
	//# If the object was encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, then ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY MUST be used to decrypt the range of the object.

	//= ../specification/s3-encryption/client.md#required-api-operations
	//# - GetObject MUST decrypt data received from the S3 server and return it as plaintext.
	m := &decryptMiddleware{
		client: c,
		input:  input,
	}
	decryptOpts := []func(*s3.Options){
		internal.AddS3CryptoUserAgent,
		m.addDecryptAPIOptions,
	}

	opts := append(optFns, decryptOpts...)
	return c.Client.GetObject(ctx, input, opts...)
}

//= ../specification/s3-encryption/client.md#required-api-operations
//# - PutObject MUST be implemented by the S3EC.
//= ../specification/s3-encryption/client.md#aws-sdk-compatibility
//# The S3EC MUST adhere to the same interface for API operations as the conventional AWS SDK S3 client.

// PutObject will make encrypt the contents before sending the data to S3. Depending on the MinFileSize
// a temporary file may be used to buffer the encrypted contents to.
func (c *S3EncryptionClientV4) PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	//= ../specification/s3-encryption/client.md#required-api-operations
	//# - PutObject MUST encrypt its input data before it is uploaded to S3.
	em := &encryptMiddleware{
		ec: c,
	}

	encryptOpts := []func(*s3.Options){
		internal.AddS3CryptoUserAgent,
		em.addEncryptAPIOptions,
	}

	opts := append(optFns, encryptOpts...)
	return c.Client.PutObject(ctx, input, opts...)
}

//= ../specification/s3-encryption/client.md#required-api-operations
//# - DeleteObject MUST be implemented by the S3EC.

// DeleteObject will defer to the underlying S3 client to delete the object,
// but will execute its own logic to delete the associated instruction file using the default instruction file suffix.
func (c *S3EncryptionClientV4) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	//= ../specification/s3-encryption/client.md#required-api-operations
	//# - DeleteObject MUST delete the given object key.
	result, err := c.Client.DeleteObject(ctx, input, optFns...)
	if err != nil {
		return result, err
	}

	//= ../specification/s3-encryption/client.md#required-api-operations
	//# - DeleteObject MUST delete the associated instruction file using the default instruction file suffix.
	
	// Delete the associated instruction file
	instructionFileKey := *input.Key + internal.DefaultInstructionKeySuffix
	instructionInput := &s3.DeleteObjectInput{
		Bucket: input.Bucket,
		Key:    &instructionFileKey,
	}
	
	// Delete instruction file - ignore errors as the instruction file may not exist
	_, _ = c.Client.DeleteObject(ctx, instructionInput, optFns...)
	
	return result, err
}

//= ../specification/s3-encryption/client.md#required-api-operations
//# - DeleteObjects MUST be implemented by the S3EC.

// DeleteObjects will delete multiple objects by calling DeleteObject for each object.
// This ensures that both the objects and their associated instruction files are deleted.
func (c *S3EncryptionClientV4) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {

	// We implement DeleteObjects by calling DeleteObject for each object
	// This ensures that both the object and its instruction file are deleted for each item
	var deletedObjects []types.DeletedObject
	var errors []types.Error
	
	for _, obj := range input.Delete.Objects {
		// Call our DeleteObject method which handles both object and instruction file deletion
		//= ../specification/s3-encryption/client.md#required-api-operations
		//# - DeleteObjects MUST delete each of the given objects.
		//= ../specification/s3-encryption/client.md#required-api-operations
		//# - DeleteObjects MUST delete each of the corresponding instruction files using the default instruction file suffix.
		deleteResult, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: input.Bucket,
			Key:    obj.Key,
		}, optFns...)
		
		if err != nil {
			// Add error to the errors list
			errors = append(errors, types.Error{
				Key:     obj.Key,
				Code:    aws.String("InternalError"),
				Message: aws.String(err.Error()),
			})
		} else {
			// Add successful deletion to the deleted objects list
			deletedObjects = append(deletedObjects, types.DeletedObject{
				Key:          obj.Key,
				DeleteMarker: deleteResult.DeleteMarker,
				VersionId:    deleteResult.VersionId,
			})
		}
	}
	
	// Build the response
	result := &s3.DeleteObjectsOutput{
		Deleted: deletedObjects,
	}
	
	// Add errors if any occurred
	if len(errors) > 0 {
		result.Errors = errors
	}
	
	return result, nil
}

// S3EC Go V4 does not implement the following operations:
// - CreateMultipartUpload
// - UploadPart
// - CompleteMultipartUpload
// - AbortMultipartUpload
// - ReEncryptInstructionFile

//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - CreateMultipartUpload MAY be implemented by the S3EC.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - If implemented, CreateMultipartUpload MUST initiate a multipart upload.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - UploadPart MAY be implemented by the S3EC.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - UploadPart MUST encrypt each part.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - Each part MUST be encrypted in sequence.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - Each part MUST be encrypted using the same cipher instance for each part.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - CompleteMultipartUpload MAY be implemented by the S3EC.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - CompleteMultipartUpload MUST complete the multipart upload.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - AbortMultipartUpload MAY be implemented by the S3EC.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - AbortMultipartUpload MUST abort the multipart upload.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - ReEncryptInstructionFile MAY be implemented by the S3EC.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - ReEncryptInstructionFile MUST decrypt the instruction file's encrypted data key for the given object using the client's CMM.
//= ../specification/s3-encryption/client.md#optional-api-operations
//= type=exception
//# - ReEncryptInstructionFile MUST re-encrypt the plaintext data key with a provided keyring.
