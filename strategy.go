package s3crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// SaveStrategyRequest represents a request sent to a SaveStrategy to save the contents of an Envelope
type SaveStrategyRequest struct {
	// The envelope to save
	Envelope *Envelope

	// The HTTP request being built
	HTTPRequest *http.Request

	// The operation input type
	Input interface{}
}

// SaveStrategy is how the data's metadata wants to be saved
type SaveStrategy interface {
	Save(context.Context, *SaveStrategyRequest) error
}

// S3SaveStrategy will save the metadata to a separate instruction file in S3
type S3SaveStrategy struct {
	APIClient             PutObjectAPIClient
	InstructionFileSuffix string
}

// Save will save the envelope contents to s3.
func (strat S3SaveStrategy) Save(ctx context.Context, req *SaveStrategyRequest) error {
	input := req.Input.(*s3.PutObjectInput)
	b, err := json.Marshal(req.Envelope)
	if err != nil {
		return err
	}

	instInput := s3.PutObjectInput{
		Bucket: input.Bucket,
		Body:   bytes.NewReader(b),
	}

	if strat.InstructionFileSuffix == "" {
		instInput.Key = aws.String(*input.Key + DefaultInstructionKeySuffix)
	} else {
		instInput.Key = aws.String(*input.Key + strat.InstructionFileSuffix)
	}

	_, err = strat.APIClient.PutObject(ctx, &instInput)
	return err
}

// HeaderV2SaveStrategy will save the metadata of the crypto contents to the header of
// the object.
type HeaderV2SaveStrategy struct{}

// Save will save the envelope to the request's header.
func (strat HeaderV2SaveStrategy) Save(ctx context.Context, req *SaveStrategyRequest) error {
	input := req.Input.(*s3.PutObjectInput)
	if input.Metadata == nil {
		input.Metadata = map[string]string{}
	}

	env := req.Envelope
	input.Metadata[http.CanonicalHeaderKey(keyV2Header)] = env.CipherKey
	input.Metadata[http.CanonicalHeaderKey(ivHeader)] = env.IV
	input.Metadata[http.CanonicalHeaderKey(matDescHeader)] = env.MatDesc
	input.Metadata[http.CanonicalHeaderKey(wrapAlgorithmHeader)] = env.WrapAlg
	input.Metadata[http.CanonicalHeaderKey(cekAlgorithmHeader)] = env.CEKAlg
	input.Metadata[http.CanonicalHeaderKey(unencryptedContentLengthHeader)] = env.UnencryptedContentLen

	if len(env.TagLen) > 0 {
		input.Metadata[http.CanonicalHeaderKey(tagLengthHeader)] = env.TagLen
	}
	return nil
}

// LoadStrategyRequest represents a request sent to a LoadStrategy to load the contents of an Envelope
type LoadStrategyRequest struct {
	// The HTTP response
	HTTPResponse *http.Response

	// The operation input type
	Input interface{}
}

// LoadStrategy ...
type LoadStrategy interface {
	Load(context.Context, *LoadStrategyRequest) (Envelope, error)
}

// S3LoadStrategy will load the instruction file from s3
type S3LoadStrategy struct {
	APIClient             GetObjectAPIClient
	InstructionFileSuffix string
}

// Load from a given instruction file suffix
func (load S3LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (Envelope, error) {
	env := Envelope{}
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

// HeaderV2LoadStrategy will load the envelope from the metadata
type HeaderV2LoadStrategy struct{}

// Load from a given object's header
func (load HeaderV2LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (Envelope, error) {
	env := Envelope{}
	env.CipherKey = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, keyV2Header}, "-"))
	env.IV = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, ivHeader}, "-"))
	env.MatDesc = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, matDescHeader}, "-"))
	env.WrapAlg = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, wrapAlgorithmHeader}, "-"))
	env.CEKAlg = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, cekAlgorithmHeader}, "-"))
	env.TagLen = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, tagLengthHeader}, "-"))
	env.UnencryptedContentLen = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, unencryptedContentLengthHeader}, "-"))
	return env, nil
}

type defaultV2LoadStrategy struct {
	client GetObjectAPIClient
	suffix string
}

func (load defaultV2LoadStrategy) Load(ctx context.Context, req *LoadStrategyRequest) (Envelope, error) {
	if value := req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, keyV2Header}, "-")); value != "" {
		strat := HeaderV2LoadStrategy{}
		return strat.Load(ctx, req)
	} else if value = req.HTTPResponse.Header.Get(strings.Join([]string{metaHeader, keyV1Header}, "-")); value != "" {
		return Envelope{}, &smithy.GenericAPIError{
			Code:    "V1NotSupportedError",
			Message: "The AWS SDK for Go does not support version 1",
		}
	}

	strat := S3LoadStrategy{
		APIClient:             load.client,
		InstructionFileSuffix: load.suffix,
	}
	return strat.Load(ctx, req)
}
