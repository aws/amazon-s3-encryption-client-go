// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package awstesting

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"io"
	"net/http"
)

func init() {
	config = aws.Config{}
	config.Region = "mock-region"
	config.Credentials = StubCredentialsProvider{}
}

// StubCredentialsProvider provides a stub credential provider that returns
// static credentials that never expire.
type StubCredentialsProvider struct{}

// Retrieve satisfies the CredentialsProvider interface. Returns stub
// credential value, and never error.
func (StubCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "SESSION",
		Source: "unit test credentials",
	}, nil
}

var config aws.Config

// Config returns a copy of the mock configuration for unit tests.
func Config() aws.Config { return config.Copy() }

// MockHttpClient is a simple utility for mocking HTTP responses and capturing requests
type MockHttpClient struct {
	Response      *http.Response
	ResponseError error
	CapturedReq   *http.Request
	CapturedBody  []byte
}

func (m *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	m.CapturedReq = req
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		m.CapturedBody = body
	}

	return m.Response, m.ResponseError
}

// TestEndpointResolver returns an endpoint resolver that uses the given URL for the resolved endpoint
func TestEndpointResolver(url string) aws.EndpointResolverWithOptions {
	return aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		endpoint := aws.Endpoint{
			URL:           url,
			PartitionID:   "aws",
			SigningMethod: region,
			SigningName:   service,
		}

		return endpoint, nil
	})
}
