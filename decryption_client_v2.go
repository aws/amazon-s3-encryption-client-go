package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// GetObjectAPIClient is a client that implements the GetObject operation
type GetObjectAPIClient interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// DecryptionClientV2 is an S3 crypto client. The decryption client
// will handle all get object requests from Amazon S3.
// Supported key wrapping algorithms:
//   - AWS KMS
//   - AWS KMS + Context
//
// Supported content ciphers:
//   - AES/GCM
//   - AES/CBC
type DecryptionClientV2 struct {
	apiClient GetObjectAPIClient
	options   DecryptionClientOptions
}

// DecryptionClientOptions is the configuration options for DecryptionClientV2.
type DecryptionClientOptions struct {
	// LoadStrategy is used to load the metadata either from the metadata of the object
	// or from a separate file in s3.
	//
	// Defaults to our default load strategy.
	LoadStrategy LoadStrategy

	CryptoRegistry *CryptoRegistry
}

// NewDecryptionClientV2 instantiates a new DecryptionClientV2. The NewDecryptionClientV2 must be configured with the
// desired key wrapping and content encryption algorithms that are required to be read by the client. These algorithms
// are registered by providing the client a CryptoRegistry that has been constructed with the desired configuration.
// NewDecryptionClientV2 will return an error if no key wrapping or content encryption algorithms have been provided.
//
// Example:
//
//	ctx := context.Background()
//	cfg, err := config.LoadDefaultConfig(ctx)
//	if err != nil {
//		panic(err) // handle err
//	}
//	s3Client := s3.NewFromConfig(cfg)
//	kmsClient := kms.NewFromConfig(cfg)
//	cr := s3crypto.NewCryptoRegistry()
//
//	if err := s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kmsClient); err != nil {
//		panic(err) // handle err
//	}
//
//	if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
//		panic(err) // handle err
//	}
//
//	client, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
//	if err != nil {
//		panic(err) // handle err
//	}
func NewDecryptionClientV2(apiClient GetObjectAPIClient, cryptoRegistry *CryptoRegistry, optFns ...func(*DecryptionClientOptions)) (*DecryptionClientV2, error) {
	clientOptions := DecryptionClientOptions{
		LoadStrategy:   defaultV2LoadStrategy{},
		CryptoRegistry: cryptoRegistry,
	}
	for _, fn := range optFns {
		fn(&clientOptions)
	}

	if err := cryptoRegistry.valid(); err != nil {
		return nil, err
	}

	decryptClient := &DecryptionClientV2{
		apiClient: apiClient,
		options:   clientOptions,
	}

	return decryptClient, nil
}

// GetObject will make a request to s3 and retrieve the object. In this process
// decryption will be done. The SDK only supports V2 reads of KMS and GCM.
func (c *DecryptionClientV2) GetObject(ctx context.Context, input *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	// TODO - updated docs
	m := &decryptMiddleware{
		client: c,
		input:  input,
	}
	decryptOpts := []func(*s3.Options){
		addS3CryptoUserAgent,
		m.addDecryptAPIOptions,
	}

	opts := append(optFns, decryptOpts...)
	return c.apiClient.GetObject(ctx, input, opts...)
}

func (m *decryptMiddleware) addDecryptAPIOptions(options *s3.Options) {
	options.APIOptions = append(options.APIOptions,
		m.addDecryptMiddleware,
	)
}

func (m *decryptMiddleware) addDecryptMiddleware(stack *middleware.Stack) error {
	return stack.Deserialize.Add(m, middleware.Before)
}

const decryptMiddlewareID = "S3Decrypt"

type decryptMiddleware struct {
	client *DecryptionClientV2
	input  *s3.GetObjectInput
}

// ID returns the resolver identifier
func (m *decryptMiddleware) ID() string {
	return decryptMiddlewareID
}

func (m *decryptMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	// call down the stack and get the deserialized result (decrypt middleware runs after the operation deserializer)
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	httpResp, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
	}

	result, ok := out.Result.(*s3.GetObjectOutput)
	if !ok {
		return out, metadata, fmt.Errorf("expected GetObjectOutput; got %v", out)
	}

	loadReq := &LoadStrategyRequest{
		HTTPResponse: httpResp.Response,
		Input:        m.input,
	}

	envelope, err := m.client.options.LoadStrategy.Load(ctx, loadReq)
	if err != nil {
		return out, metadata, fmt.Errorf("failed to load envelope: bucket=%v; key=%v; err=%w", m.input.Bucket, m.input.Key, err)
	}

	cipher, err := contentCipherFromEnvelope(ctx, m.client.options, envelope)
	if err != nil {
		return out, metadata, err
	}

	reader, err := cipher.DecryptContents(result.Body)
	if err != nil {
		return out, metadata, err
	}

	result.Body = reader
	out.Result = result

	return out, metadata, err
}
