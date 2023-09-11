package s3crypto

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"log"
)

const customTypeWarningMessage = "WARNING: The S3 Encryption Client is configured to write encrypted objects using types not provided by AWS. Security and compatibility with these types can not be guaranteed."

type S3EncryptionClientV3 struct {
	*s3.Client                            // promoted anonymous field, it allows this type to call s3 Client methods
	wrappedClient *s3.Client              // contains the "wrapped" s3 Client, which is used within crypto-specific overrides
	options       EncryptionClientOptions // options for encrypt/decrypt
}

// NewS3EncryptionClientV3 creates a new S3 client which can encrypt and decrypt
func NewS3EncryptionClientV3(s3Client *s3.Client, cryptoRegistry *CryptoRegistry, contentCipherBuilder ContentCipherBuilder, optFns ...func(options *EncryptionClientOptions)) (*S3EncryptionClientV3, error) {
	wrappedClient := s3Client
	// default options
	options := EncryptionClientOptions{
		SaveStrategy:         HeaderV2SaveStrategy{},
		MinFileSize:          DefaultMinFileSize,
		Logger:               log.Default(),
		LoadStrategy:         defaultV2LoadStrategy{},
		CryptoRegistry:       cryptoRegistry,
		ContentCipherBuilder: contentCipherBuilder,
	}
	for _, fn := range optFns {
		fn(&options)
	}

	// Check if the passed in type is a fixture, if not log a warning message to the user
	if fixture, ok := contentCipherBuilder.(awsFixture); !ok || !fixture.isAWSFixture() {
		options.Logger.Println(customTypeWarningMessage)
	}

	if err := cryptoRegistry.valid(); err != nil {
		return nil, err
	}

	// use the given wrappedClient for the promoted anon fields AND the crypto calls
	s3ec := &S3EncryptionClientV3{wrappedClient, wrappedClient, options}
	return s3ec, nil
}

func NewS3DecryptionOnlyClientV3(s3Client *s3.Client, cryptoRegistry *CryptoRegistry, optFns ...func(options *EncryptionClientOptions)) (*S3EncryptionClientV3, error) {
	wrappedClient := s3Client
	// default options
	options := EncryptionClientOptions{
		SaveStrategy:         HeaderV2SaveStrategy{},
		MinFileSize:          DefaultMinFileSize,
		Logger:               log.Default(),
		LoadStrategy:         defaultV2LoadStrategy{},
		CryptoRegistry:       cryptoRegistry,
		ContentCipherBuilder: nil, // nil ContentCipherBuilder because encryption is forbidden
	}
	for _, fn := range optFns {
		fn(&options)
	}

	if err := cryptoRegistry.valid(); err != nil {
		return nil, err
	}

	// use the given wrappedClient for the promoted anon fields AND the crypto calls
	s3ec := &S3EncryptionClientV3{wrappedClient, wrappedClient, options}
	return s3ec, nil
}

// NewS3EncryptionOnlyClientV3 creates a new encryption-only S3 crypto client
func NewS3EncryptionOnlyClientV3(s3Client *s3.Client, contentCipherBuilder ContentCipherBuilder, optFns ...func(options *EncryptionClientOptions)) (*S3EncryptionClientV3, error) {
	wrappedClient := s3Client
	// default options
	options := EncryptionClientOptions{
		SaveStrategy:         HeaderV2SaveStrategy{},
		MinFileSize:          DefaultMinFileSize,
		Logger:               log.Default(),
		LoadStrategy:         defaultV2LoadStrategy{},
		CryptoRegistry:       nil, // nil CryptoRegistry as decryption is forbidden
		ContentCipherBuilder: contentCipherBuilder,
	}
	for _, fn := range optFns {
		fn(&options)
	}

	// Check if the passed in type is a fixture, if not log a warning message to the user
	if fixture, ok := contentCipherBuilder.(awsFixture); !ok || !fixture.isAWSFixture() {
		options.Logger.Println(customTypeWarningMessage)
	}

	// use the given wrappedClient for the promoted anon fields AND the crypto calls
	s3ec := &S3EncryptionClientV3{wrappedClient, wrappedClient, options}
	return s3ec, nil

}

// GetObject will make a request to s3 and retrieve the object. In this process
// decryption will be done. The SDK only supports region reads of KMS and GCM.
func (c *S3EncryptionClientV3) GetObject(ctx context.Context, input *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	m := &decryptMiddleware{
		client: c,
		input:  input,
	}
	decryptOpts := []func(*s3.Options){
		addS3CryptoUserAgent,
		m.addDecryptAPIOptions,
	}

	opts := append(optFns, decryptOpts...)
	return c.wrappedClient.GetObject(ctx, input, opts...)
}

// PutObject will make encrypt the contents before sending the data to S3. Depending on the MinFileSize
// a temporary file may be used to buffer the encrypted contents to.
func (c *S3EncryptionClientV3) PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	em := &encryptMiddleware{
		ec: c,
	}

	encryptOpts := []func(*s3.Options){
		addS3CryptoUserAgent,
		em.addEncryptAPIOptions,
	}

	opts := append(optFns, encryptOpts...)
	return c.wrappedClient.PutObject(ctx, input, opts...)
}

type EncryptionClientOptions struct {
	// Cipher builder for each request
	ContentCipherBuilder ContentCipherBuilder

	// SaveStrategy will dictate where the envelope is saved.
	//
	// Defaults to the object's metadata
	SaveStrategy SaveStrategy

	// TempFolderPath is used to store temp files when calling PutObject.
	// Temporary files are needed to compute the X-Amz-Content-Sha256 header.
	TempFolderPath string

	// MinFileSize is the minimum size for the content to write to a
	// temporary file instead of using memory.
	MinFileSize int64

	// The logger to write logging messages to.
	Logger *log.Logger

	// LoadStrategy is used to load the metadata either from the metadata of the object
	// or from a separate file in s3.
	//
	// Defaults to our default load strategy.
	LoadStrategy LoadStrategy

	CryptoRegistry *CryptoRegistry
}
