package s3crypto

import (
	"context"
	"encoding/hex"
	"fmt"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"io"
	"log"
)

const customTypeWarningMessage = "WARNING: The S3 Encryption Client is configured to write encrypted objects using types not provided by AWS. Security and compatibility with these types can not be guaranteed."

// DefaultMinFileSize is used to check whether we want to write to a temp file
// or store the data in memory.
const DefaultMinFileSize = 1024 * 512 * 5

// PutObjectAPIClient is a client that implements the PutObject operation
type PutObjectAPIClient interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// EncryptionClientV2 is an S3 crypto client.
type EncryptionClientV2 struct {
	apiClient PutObjectAPIClient
	options   EncryptionClientOptions
}

// EncryptionClientOptions is the configuration options for EncryptionClientV2
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
}

// NewEncryptionClientV2 instantiates a new S3 crypto client.
//
// Example:
//
//	ctx := context.Background()
//	cfg, err := config.LoadDefaultConfig(ctx)
//	if err != nil {
//		panic(err) // handle err
//	}
//
//	s3Client := s3.NewFromConfig(cfg)
//	kmsClient := kms.NewFromConfig(cfg)
//
//	cmkID := "arn:aws:kms:region:000000000000:key/00000000-0000-0000-0000-000000000000"
//	var matDesc s3crypto.MaterialDescription
//	handler := s3crypto.NewKMSContextKeyGenerator(kmsClient, cmkID, matDesc)
//	cipherBuilder := s3crypto.AESGCMContentCipherBuilderV2(handler)
//	client := s3crypto.NewEncryptionClientV2(s3Client, cipherBuilder)
func NewEncryptionClientV2(apiClient PutObjectAPIClient, contentCipherBuilder ContentCipherBuilder, optFns ...func(*EncryptionClientOptions)) *EncryptionClientV2 {
	clientOptions := EncryptionClientOptions{
		ContentCipherBuilder: contentCipherBuilder,
		SaveStrategy:         HeaderV2SaveStrategy{},
		MinFileSize:          DefaultMinFileSize,
		Logger:               log.Default(),
	}

	for _, fn := range optFns {
		fn(&clientOptions)
	}

	// Check if the passed in type is a fixture, if not log a warning message to the user
	if fixture, ok := contentCipherBuilder.(awsFixture); !ok || !fixture.isAWSFixture() {
		clientOptions.Logger.Println(customTypeWarningMessage)
	}

	encClient := &EncryptionClientV2{
		apiClient: apiClient,
		options:   clientOptions,
	}

	return encClient
}

// PutObject will make encrypt the contents before sending the data to S3. Depending on the MinFileSize
// a temporary file may be used to buffer the encrypted contents to.
func (c *EncryptionClientV2) PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	em := &encryptMiddleware{
		ec:    c,
		input: input,
	}

	encryptOpts := []func(*s3.Options){
		addS3CryptoUserAgent,
		em.addEncryptAPIOptions,
	}

	opts := append(optFns, encryptOpts...)
	return c.apiClient.PutObject(ctx, input, opts...)
}

func (m *encryptMiddleware) addEncryptAPIOptions(options *s3.Options) {
	options.APIOptions = append(options.APIOptions,
		// remove default sha256 payload computation (taken care of by encryption middleware)
		v4.RemoveComputePayloadSHA256Middleware,
		m.addEncryptMiddleware,
	)
}

func (m *encryptMiddleware) addEncryptMiddleware(stack *middleware.Stack) error {
	return stack.Build.Add(m, middleware.Before)
}

const encryptMiddlewareID = "S3Encrypt"

type encryptMiddleware struct {
	ec    *EncryptionClientV2
	input *s3.PutObjectInput
}

// ID returns the resolver identifier
func (m *encryptMiddleware) ID() string {
	return encryptMiddlewareID
}

// HandleBuild replaces the request body with an encrypted version
func (m *encryptMiddleware) HandleBuild(
	ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler,
) (
	out middleware.BuildOutput, metadata middleware.Metadata, err error,
) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown transport type %T", in.Request)
	}

	// TODO - customize errors?

	n, ok, err := req.StreamLength()
	if !ok || err != nil {
		return out, metadata, err
	}

	dst, err := getWriterStore(m.ec.options.TempFolderPath, n >= m.ec.options.MinFileSize)
	if err != nil {
		return out, metadata, err
	}

	var encryptor ContentCipher
	cipherBuilder := m.ec.options.ContentCipherBuilder
	if v, ok := cipherBuilder.(ContentCipherBuilderWithContext); ok {
		encryptor, err = v.ContentCipherWithContext(ctx)
	} else {
		encryptor, err = cipherBuilder.ContentCipher()
	}

	if err != nil {
		return out, metadata, err
	}

	stream := req.GetStream()
	lengthReader := newContentLengthReader(stream)
	sha := newSHA256Writer(dst)
	reader, err := encryptor.EncryptContents(lengthReader)
	if err != nil {
		return out, metadata, err
	}

	_, err = io.Copy(sha, reader)
	if err != nil {
		return out, metadata, err
	}

	data := encryptor.GetCipherData()
	envelope, err := encodeMeta(lengthReader, data)
	if err != nil {
		return out, metadata, err
	}

	// set the precomputed payload hash to encrypted hash value, this is consumed downstream by signing middleware
	shaHex := hex.EncodeToString(sha.GetValue())
	ctx = v4.SetPayloadHash(ctx, shaHex)

	// update the request body to encrypted contents
	if req, err = req.SetStream(dst); err != nil {
		return out, metadata, err
	}

	// rewind
	if err = req.RewindStream(); err != nil {
		return out, metadata, err
	}

	// save the metadata
	saveReq := &SaveStrategyRequest{
		Envelope:    &envelope,
		HTTPRequest: req.Request,
		Input:       m.input,
	}

	// this copies the required crypto params (IV, tag length, etc.)
	// into saveReq.HTTPRequest.Headers (req.Request)
	if err = m.ec.options.SaveStrategy.Save(ctx, saveReq); err != nil {
		return out, metadata, err
	}

	// set the middleware input's Request to req
	in.Request = req
	return next.HandleBuild(ctx, in)
}
