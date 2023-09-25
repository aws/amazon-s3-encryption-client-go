package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"io"
)

// DefaultMinFileSize is used to check whether we want to write to a temp file
// or store the data in memory.
const DefaultMinFileSize = 1024 * 512 * 5

// PutObjectAPIClient is a client that implements the PutObject operation
type PutObjectAPIClient interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func (m *encryptMiddleware) addEncryptAPIOptions(options *s3.Options) {
	options.APIOptions = append(options.APIOptions,
		m.addEncryptMiddleware,
	)
}

func (m *encryptMiddleware) addEncryptMiddleware(stack *middleware.Stack) error {
	return stack.Serialize.Add(m, middleware.Before)
}

const encryptMiddlewareID = "S3Encrypt"

type encryptMiddleware struct {
	ec *S3EncryptionClientV3
}

// ID returns the resolver identifier
func (m *encryptMiddleware) ID() string {
	return encryptMiddlewareID
}

// HandleSerialize replaces the request body with an encrypted version and saves the envelope using the save strategy
func (m *encryptMiddleware) HandleSerialize(
	ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler,
) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {

	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*s3.PutObjectInput)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	// TODO - customize errors?
	reqCopy, err := req.SetStream(input.Body)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	n, ok, err := reqCopy.StreamLength()
	if !ok || err != nil {
		return out, metadata, err
	}

	dst, err := getWriterStore(m.ec.options.TempFolderPath, n >= m.ec.options.MinFileSize)
	if err != nil {
		return out, metadata, err
	}

	// in V3, AES GCM is the only supported content cipher
	var encryptor, _ = AESGCMContentCipherBuilder(m.ec.options.CipherDataGeneratorWithCEKAlg).ContentCipher()

	if err != nil {
		return out, metadata, err
	}

	stream := reqCopy.GetStream()
	lengthReader := newContentLengthReader(stream)
	reader, err := encryptor.EncryptContents(lengthReader)
	if err != nil {
		return out, metadata, err
	}

	_, err = io.Copy(dst, reader)
	if err != nil {
		return out, metadata, err
	}

	data := encryptor.GetCipherData()
	envelope, err := encodeMeta(lengthReader, data)
	if err != nil {
		return out, metadata, err
	}

	// rewind
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return out, metadata, err
	}

	// update the request body to encrypted contents
	input.Body = dst

	// save the metadata
	saveReq := &SaveStrategyRequest{
		Envelope:    &envelope,
		HTTPRequest: req.Request,
		Input:       input,
	}

	// this saves the required crypto params (IV, tag length, etc.)
	if err = m.ec.options.SaveStrategy.Save(ctx, saveReq); err != nil {
		return out, metadata, err
	}

	// update the middleware input's parameter which is what the generated serialize step will use
	in.Parameters = input

	out, metadata, err = next.HandleSerialize(ctx, in)

	// cleanup any temp files after the request is made
	dst.cleanup()
	return out, metadata, err
}
