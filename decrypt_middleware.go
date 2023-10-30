package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"strings"
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

	// determine the content algorithm from metadata
	// this is purposefully done before attempting to
	// decrypt the materials
	var cekFunc CEKEntry
	if objectMetadata.CEKAlg == AESGCMNoPadding {
		cekFunc = newAESGCMContentCipher
	} else if strings.Contains(objectMetadata.CEKAlg, "AES/CBC") {
		if !m.client.options.EnableLegacyModes {
			return out, metadata, fmt.Errorf("configure client with enable legacy modes set to true to decrypt with %s", objectMetadata.CEKAlg)
		}
		cekFunc = newAESCBCContentCipher
	} else {
		return out, metadata, fmt.Errorf("invalid content encryption algorithm found in metadata: %s", objectMetadata.CEKAlg)
	}

	decryptMaterials, err := m.client.options.CryptographicMaterialsManager.DecryptMaterials(ctx, objectMetadata)
	if err != nil {
		return out, metadata, fmt.Errorf("error while decrypting materials: %v", err)
	}

	cipher, err := cekFunc(*decryptMaterials)
	cipher.DecryptContents(result.Body)
	reader, err := cipher.DecryptContents(result.Body)
	if err != nil {
		return out, metadata, err
	}

	result.Body = reader
	out.Result = result

	return out, metadata, err
}
