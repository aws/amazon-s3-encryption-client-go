package client

import (
	"context"
	"github.com/aws/amazon-s3-encryption-client-go/internal"
	"github.com/aws/amazon-s3-encryption-client-go/materials"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3EncryptionClientV3 provides client-side encryption for S3.
// The client embeds a default client to provide support for control plane operations
// which do not involve encryption.
type S3EncryptionClientV3 struct {
	*s3.Client                         // promoted anonymous field, it allows this type to call s3 Client methods
	Options    EncryptionClientOptions // options for encrypt/decrypt
}

// EncryptionClientOptions is the configuration options for the S3 Encryption Client.
type EncryptionClientOptions struct {
	// TempFolderPath is used to store temp files when calling PutObject
	// Temporary files are needed to compute the X-Amz-Content-Sha256 header
	TempFolderPath string

	// MinFileSize is the minimum size for the content to write to a
	// temporary file instead of using memory
	MinFileSize int64

	// The logger to write logging messages to
	Logger *log.Logger

	// The CryptographicMaterialsManager to use to manage encryption and decryption materials
	CryptographicMaterialsManager materials.CryptographicMaterialsManager

	// EnableLegacyUnauthenticatedModes MUST be set to true in order to decrypt objects encrypted
	//using legacy (unauthenticated) modes such as AES/CBC
	EnableLegacyUnauthenticatedModes bool
}

// New creates a new S3 Encryption Client v3 with the given CryptographicMaterialsManager
func New(s3Client *s3.Client, CryptographicMaterialsManager materials.CryptographicMaterialsManager, optFns ...func(options *EncryptionClientOptions)) (*S3EncryptionClientV3, error) {
	wrappedClient := s3Client
	// default options
	options := EncryptionClientOptions{
		MinFileSize:                      DefaultMinFileSize,
		Logger:                           log.Default(),
		CryptographicMaterialsManager:    CryptographicMaterialsManager,
		EnableLegacyUnauthenticatedModes: false,
	}
	for _, fn := range optFns {
		fn(&options)
	}

	// use the given wrappedClient for the promoted anon fields
	s3ec := &S3EncryptionClientV3{wrappedClient, options}
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
		internal.AddS3CryptoUserAgent,
		m.addDecryptAPIOptions,
	}

	opts := append(optFns, decryptOpts...)
	return c.Client.GetObject(ctx, input, opts...)
}

// PutObject will make encrypt the contents before sending the data to S3. Depending on the MinFileSize
// a temporary file may be used to buffer the encrypted contents to.
func (c *S3EncryptionClientV3) PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
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
