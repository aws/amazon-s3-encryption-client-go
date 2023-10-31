package s3crypto

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// SaveStrategyRequest represents a request sent to a SaveStrategy to save the contents of an ObjectMetadata
type SaveStrategyRequest struct {
	// The envelope to save
	Envelope *ObjectMetadata

	// The HTTP request being built
	HTTPRequest *http.Request

	// The operation input type
	Input interface{}
}

// ObjectMetadataSaveStrategy will save the metadata of the crypto contents to the header of
// the object.
type ObjectMetadataSaveStrategy struct{}

// Save will save the envelope to the request's header.
func (strat ObjectMetadataSaveStrategy) Save(ctx context.Context, saveReq *SaveStrategyRequest) error {

	input := saveReq.Input.(*s3.PutObjectInput)
	if input.Metadata == nil {
		input.Metadata = map[string]string{}
	}

	env := saveReq.Envelope
	input.Metadata[http.CanonicalHeaderKey(keyV2Header)] = env.CipherKey
	input.Metadata[http.CanonicalHeaderKey(ivHeader)] = env.IV
	input.Metadata[http.CanonicalHeaderKey(matDescHeader)] = env.MatDesc
	input.Metadata[http.CanonicalHeaderKey(KeyringAlgorithmHeader)] = env.KeyringAlg
	input.Metadata[http.CanonicalHeaderKey(cekAlgorithmHeader)] = env.CEKAlg
	input.Metadata[http.CanonicalHeaderKey(unencryptedContentLengthHeader)] = env.UnencryptedContentLen

	if len(env.TagLen) > 0 {
		input.Metadata[http.CanonicalHeaderKey(tagLengthHeader)] = env.TagLen
	}
	return nil
}

// LoadStrategyRequest represents a request sent to a LoadStrategy to load the contents of an ObjectMetadata
type LoadStrategyRequest struct {
	// The HTTP response
	HTTPResponse *http.Response

	// The operation input type
	Input interface{}
}

// LoadStrategy ...
type LoadStrategy interface {
	Load(context.Context, *LoadStrategyRequest) (ObjectMetadata, error)
}

// S3LoadStrategy will load the instruction file from s3
type s3LoadStrategy struct {
	APIClient             GetObjectAPIClient
	InstructionFileSuffix string
}

// Load from a given instruction file suffix
func (load s3LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (ObjectMetadata, error) {
	env := ObjectMetadata{}
	if load.InstructionFileSuffix == "" {
		load.InstructionFileSuffix = DefaultInstructionKeySuffix
	}

	input := req.Input.(*s3.GetObjectInput)
	out, err := load.APIClient.GetObject(ctx, &s3.GetObjectInput{
		Key:    aws.String(strings.Join([]string{*input.Key, load.InstructionFileSuffix}, "")),
		Bucket: input.Bucket,
	})

	if err != nil {
		return env, err
	}

	b, err := io.ReadAll(out.Body)
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(b, &env)
	return env, err
}

// headerV2LoadStrategy will load the envelope from the metadata
type headerV2LoadStrategy struct{}

// Load from a given object's header
func (load headerV2LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (ObjectMetadata, error) {
	env := ObjectMetadata{}
	env.CipherKey = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, keyV2Header}, "-"))
	env.IV = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, ivHeader}, "-"))
	env.MatDesc = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, matDescHeader}, "-"))
	env.KeyringAlg = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, KeyringAlgorithmHeader}, "-"))
	env.CEKAlg = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, cekAlgorithmHeader}, "-"))
	env.TagLen = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, tagLengthHeader}, "-"))
	env.UnencryptedContentLen = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, unencryptedContentLengthHeader}, "-"))
	return env, nil
}

// DefaultV2LoadStrategy This is the only exported LoadStrategy since cx are no longer able to configure their client
// with a specific load strategy. Instead, we figure out which strategy to use based on the response header on decrypt.
type DefaultV2LoadStrategy struct {
	client GetObjectAPIClient
	suffix string
}

func (load DefaultV2LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (ObjectMetadata, error) {
	if value := req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, keyV2Header}, "-")); value != "" {
		strat := headerV2LoadStrategy{}
		return strat.Load(ctx, req)
	} else if value = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, keyV1Header}, "-")); value != "" {
		// TODO look into this - this does not make sense.
		return ObjectMetadata{}, &smithy.GenericAPIError{
			Code:    "V1NotSupportedError",
			Message: "The AWS SDK for Go does not support version 1",
		}
	}

	strat := s3LoadStrategy{
		APIClient:             load.client,
		InstructionFileSuffix: load.suffix,
	}
	return strat.Load(ctx, req)
}
