package s3crypto

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"log"
)

const customTypeWarningMessage = "WARNING: The S3 Encryption Client is configured to write encrypted objects using types not provided by AWS. Security and compatibility with these types can not be guaranteed."

type S3EncryptionClientV3 struct {
	*s3.Client                         // promoted anonymous field, it allows this type to call s3 Client methods
	options    EncryptionClientOptions // options for encrypt/decrypt
}

type EncryptionClientOptions struct {
	// Keyring for encryption/decryption
	// TODO: Fully refactor away in favor of CMM
	CipherDataGeneratorWithCEKAlg CipherDataGeneratorWithCEKAlg

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

	CryptographicMaterialsManager *CryptographicMaterialsManager
}

// NewS3EncryptionClientV3 creates a new S3 client which can encrypt and decrypt
func NewS3EncryptionClientV3(s3Client *s3.Client, CryptographicMaterialsManager *CryptographicMaterialsManager, keyring CipherDataGeneratorWithCEKAlg, optFns ...func(options *EncryptionClientOptions)) (*S3EncryptionClientV3, error) {
	wrappedClient := s3Client
	// default options
	options := EncryptionClientOptions{
		SaveStrategy:                  HeaderV2SaveStrategy{},
		MinFileSize:                   DefaultMinFileSize,
		Logger:                        log.Default(),
		LoadStrategy:                  defaultV2LoadStrategy{},
		CryptographicMaterialsManager: CryptographicMaterialsManager,
		CipherDataGeneratorWithCEKAlg: keyring,
	}
	for _, fn := range optFns {
		fn(&options)
	}

	// keyring MAY be nil,
	// in which case the client
	// becomes "decrypt-only".
	if keyring != nil {
		// Check if the passed in type is a fixture, if not log a warning message to the user
		if fixture, ok := keyring.(awsFixture); !ok || !fixture.isAWSFixture() {
			options.Logger.Println(customTypeWarningMessage)
		}
	}

	// CryptographicMaterialsManager MAY be nil,
	// in which case the client
	// becomes "encrypt-only".
	if CryptographicMaterialsManager != nil {
		if err := CryptographicMaterialsManager.valid(); err != nil {
			return nil, err
		}
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
		addS3CryptoUserAgent,
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
		addS3CryptoUserAgent,
		em.addEncryptAPIOptions,
	}

	opts := append(optFns, encryptOpts...)
	return c.Client.PutObject(ctx, input, opts...)
}
