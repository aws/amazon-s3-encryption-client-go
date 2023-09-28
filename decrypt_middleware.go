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
	client *S3EncryptionClientV3
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

	// decode metadata
	objectMetadata, err := m.client.options.LoadStrategy.Load(ctx, loadReq)
	if err != nil {
		return out, metadata, fmt.Errorf("failed to load objectMetadata: bucket=%v; key=%v; err=%w", m.input.Bucket, m.input.Key, err)
	}

	// prepare materials
	// Currently, this returns ContentCipher which is basically mats + content crypto
	// it decrypts the data key anaw
	// instead, or within, we want to instead call functions on the CMM
	//var cekAlgGen = *m.client.options.DefaultCryptographicMaterialsManager.GeneratorWithCEKAlg
	//*m.client.options.DefaultCryptographicMaterialsManager.
	//	// there should be a func on the CMM to shell out to keyring instead
	//	cekAlgGen.GenerateCipherDataWithCEKAlg(ctx, 256, len(objectMetadata.IV), objectMetadata.CEKAlg)
	materials, err := m.client.options.CryptographicMaterialsManager.decryptMaterials(ctx, objectMetadata)

	// TODO: not sure if this is the best place to put this, maybe instead where it's parsed? as early as possible?
	// TODO: make sure this check is even correct lol, it's a very weak string match prob not
	if m.client.options.EnableLegacyModes && materials.CEKAlgorithm == AESCBC {
		return out, metadata, fmt.Errorf("configure client with enable legacy modes set to true to decrypt with %s", materials.CEKAlgorithm)
	}

	cek, ok := m.client.options.CryptographicMaterialsManager.GetCEK(materials.CEKAlgorithm)
	cipher, err := cek(*materials)
	cipher.DecryptContents(result.Body)
	reader, err := cipher.DecryptContents(result.Body)
	if err != nil {
		return out, metadata, err
	}

	result.Body = reader
	out.Result = result

	return out, metadata, err
}
