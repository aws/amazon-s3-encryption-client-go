// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v3/internal/awstesting"
	"github.com/aws/amazon-s3-encryption-client-go/v3/algorithms"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v3/commitment"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecryptionClientV4_GetMockV2Object(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "hJUv7S6K2cHF64boS9ixHX0TZAjBZLT4ZpEO4XxkGnY=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("6b134eb7a353131de92faff64f594b2794e3544e31776cca26fe3bbeeffc68742d1007234f11c6670522602326868e29f37e9d2678f1614ec1a2418009b9772100929aadbed9a21a")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				http.CanonicalHeaderKey("x-amz-meta-x-amz-key-v2"):   []string{"PsuclPnlo2O0MQoov6kL1TBlaZG6oyNwWuAqmAgq7g8b9ZeeORi3VTMg624FU9jx"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-iv"):       []string{"dqqlq2dRVSQ5hFRb"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-matdesc"):  []string{`{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"}`},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{materials.KMSContextKeyring},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/GCM/NoPadding"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("test"),
	}

	out, err := client.GetObject(context.Background(), input)

	actual, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected, err := hex.DecodeString("af150d7156bf5b3f5c461e5c6ac820acc5a33aab7085d920666c250ff251209d5a4029b3bd78250fab6e11aed52fae948d407056a9519b68")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bytes.Compare(expected, actual) != 0 {
		t.Fatalf("expected content to match but it did not")
	}
}

// Use TestEncryptionClientV4_PutMockV3Object to generate a new test vector if needed.
func TestDecryptionClientV4_GetMockV3Object(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("2d4ff4dafe27f69f628872d82b5a1002ed1a21b8485d532bd8159f6487945b3641af5865fc0a029a3650053600c6d213625b9a0cc9c239577c09f3423dedc5641e88b6835824417c")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				http.CanonicalHeaderKey("x-amz-meta-x-amz-3"):   []string{"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-c"):       []string{"115"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-d"):  []string{"6JOSx47RkdyfciJkNauuC4RpkMcWZY4a+i1RzQ=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-i"): []string{"sE9zLb4tsEBJkvEhLMZFxMj9oZJBbQ6ZOgOqHA=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-t"):  []string{`{"aws:x-amz-cek-alg":"115"}`},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-w"):  []string{"12"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("test"),
	}

	out, err := client.GetObject(context.Background(), input)

	actual, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected, err := hex.DecodeString("8f2c59c6dbfcacf356f3da40788cbde67ca38161a4702cbcf757af663e1c24a600001b2f500417dbf5a050f57db6737422b2ed6a44c75e0d")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bytes.Compare(expected, actual) != 0 {
		t.Fatalf("expected content to match but it did not")
	}
}

func TestDecryptionClientV4_GetMockV3ObjectWithIncorrectKCValue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("e403a8f941e43bdf0ca3ef0bcf6701acd739b2de0a8ee524fa89497210fb0213dfc856376a9ff7753db6ee549dc4040861bc7080a66f902441904bf4a003e028e982de8ea6958c30")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				http.CanonicalHeaderKey("x-amz-meta-x-amz-3"):   []string{"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I/0X2GC1iX9Pszf1PAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMDQPII4AynCy/rVwhAgEQgDueLCWabc8WgyoZkAnqVzESQ4NztSDxuETx3obcWJ9Jj6gDAAuDaAL5V+H5QFfwgBqWEcIYt2Ep9WcECw=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-c"):       []string{"115"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-d"):  []string{"FiQepGw+/O+3MuYrmQU5mAkotUnxB+W+EwYDHw=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-i"): []string{"cPwtbK08jrpe3x+QElyG+vGtkk9jDn6KmOta2Q=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-t"):  []string{`{"aws:x-amz-cek-alg":"115"}`},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-w"):  []string{"12"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("test"),
	}

	_, err = client.GetObject(context.Background(), input)
	if err == nil {
		t.Fatalf("expected error due to incorrect key commitment, got nil")
	}
	if !strings.Contains(err.Error(), "derived key commitment value does not match value stored on encrypted message") {
		t.Fatalf("expected key commitment mismatch error, got %v", err)
	}
}

func TestDecryptionClientV4_GetMockV3ObjectWithInvalidKCValue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("e403a8f941e43bdf0ca3ef0bcf6701acd739b2de0a8ee524fa89497210fb0213dfc856376a9ff7753db6ee549dc4040861bc7080a66f902441904bf4a003e028e982de8ea6958c30")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				http.CanonicalHeaderKey("x-amz-meta-x-amz-3"):   []string{"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I/0X2GC1iX9Pszf1PAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMDQPII4AynCy/rVwhAgEQgDueLCWabc8WgyoZkAnqVzESQ4NztSDxuETx3obcWJ9Jj6gDAAuDaAL5V+H5QFfwgBqWEcIYt2Ep9WcECw=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-c"):       []string{"115"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-d"):  []string{"notvalidbase64"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-i"): []string{"cPwtbK08jrpe3x+QElyG+vGtkk9jDn6KmOta2Q=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-t"):  []string{`{"aws:x-amz-cek-alg":"115"}`},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-w"):  []string{"12"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("test"),
	}

	_, err = client.GetObject(context.Background(), input)
	if err == nil {
		t.Fatalf("expected error due to incorrect key commitment, got nil")
	}
	if !strings.Contains(err.Error(), "illegal base64 data at input byte") {
		t.Fatalf("expected base64 decoding error, got %v", err)
	}
}

func TestDecryptionClientV4_GetMockV2Object_V1Interop_KMS_AESCBC(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "7ItX9CTGNWWegC62RlaNu6EJ3+J9yGO7yAqDNU4CdeA=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("6f4f413a357a3c3a12289442fb835c5e4ecc8db1d86d3d1eab906ce07e1ad772180b2e9ec49c3fc667d8aceea8c46da6bb9738251a8e36241a473ad820f99c701906bac1f48578d5392e928889bbb1d9")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				http.CanonicalHeaderKey("x-amz-meta-x-amz-key-v2"):   []string{"/nJlgMtxMNk2ErKLLrLp3H7A7aQyJcJOClE2ldAIIFNZU4OhUMc1mMCHdIEC8fby"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-iv"):       []string{"adO9U7pcEHxUTaguIkho9g=="},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-matdesc"):  []string{`{"kms_cmk_id":"test-key-id"}`},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{materials.KMSKeyring},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/CBC/PKCS5Padding"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("test"),
	}

	out, err := client.GetObject(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	actual, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected, err := hex.DecodeString("a716e018ffecf4bb94d4352082af4662612d9c225efed6f389bf1f6f0447a9bce80cc712d7e66ee5e1c086af38e607ead351fd2c1a0247878e693ada73bd580b")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bytes.Compare(expected, actual) != 0 {
		t.Fatalf("expected content to match but it did not")
	}
}

func TestDecryptionClientV4_GetMockV2Object_V1Interop_KMS_AESGCM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "Hrjrkkt/vQwMYtqvK6+MiXh3xiMvviL1Ks7w2mgsJgU=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("6370a90b9a118301c2160c23a90d96146761276acdcfa92e6cbcb783abdc2e1813891506d6850754ef87ed2ac3bf570dd5c9da9492b7769ae1e639d073d688bd284815404ce2648a")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				http.CanonicalHeaderKey("x-amz-meta-x-amz-key-v2"):   []string{"/7tu/RFXZU1UFwRzzf11IdF3b1wBxBZhnUMjVYHKKr5DjAHS602GvXt4zYcx/MJo"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-iv"):       []string{"8Rlvyy8AoYj8v579"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-matdesc"):  []string{`{"kms_cmk_id":"test-key-id"}`},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{materials.KMSKeyring},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/GCM/NoPadding"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("test"),
	}

	out, err := client.GetObject(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	actual, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected, err := hex.DecodeString("75f6805afa7d7be4f56c5906adc27a5959158bf4af6e7c7e12bda3458300f6b1c8daaf9a5949f7a6bdbb8a9c072de05bf0541633421f42f8")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bytes.Compare(expected, actual) != 0 {
		t.Fatalf("expected content to match but it did not")
	}
}

func TestDecryptionClientV4_GetMockV2Object_OnlyDecryptsRegisteredAlgorithms(t *testing.T) {
	httpClientFactory := func() *awstesting.MockHttpClient {
		b, err := hex.DecodeString("1bd0271b25951fdef3dbe51a9b7af85f66b311e091aa10a346655068f657b9da9acc0843ea0522b0d1ae4a25a31b13605dd1ac5d002db8965d9d4652fd602693")
		if err != nil {
			t.Errorf("expected no error, but received %v", err)
		}

		return &awstesting.MockHttpClient{
			Response: &http.Response{
				StatusCode: 200,
				Header: http.Header{
					http.CanonicalHeaderKey("x-amz-meta-x-amz-key-v2"):   []string{"gNuYjzkLTzfhOcIX9h1l8jApWcAAQqzlryOE166kdDojaHH/+7cCqR5HU8Bpxmij"},
					http.CanonicalHeaderKey("x-amz-meta-x-amz-iv"):       []string{"Vmauu+TMEgaXa26ObqpARA=="},
					http.CanonicalHeaderKey("x-amz-meta-x-amz-matdesc"):  []string{`{"kms_cmk_id":"test-key-id"}`},
					http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{materials.KMSKeyring},
					http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/CBC/PKCS5Padding"},
				},
				Body: io.NopCloser(bytes.NewBuffer(b)),
			},
		}
	}

	cases := map[string]struct {
		Client  *S3EncryptionClientV3
		WantErr string
	}{
		"unsupported cek": {
			Client: func() *S3EncryptionClientV3 {
				keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kms.NewFromConfig(awstesting.Config()), func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = false
				})
				cmm, err := materials.NewCryptographicMaterialsManager(keyring)
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				tConfig := awstesting.Config()
				tConfig.HTTPClient = httpClientFactory()
				s3Client := s3.NewFromConfig(tConfig)

				client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
					clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
				})
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return client
			}(),
			WantErr: "operation error S3: GetObject, configure client with enable legacy unauthenticated modes set to true to decrypt with AES/CBC/PKCS5Padding",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			client := tt.Client
			input := &s3.GetObjectInput{
				Bucket: aws.String("test"),
				Key:    aws.String("test"),
			}

			_, err := client.GetObject(context.Background(), input)

			if err == nil {
				t.Fatalf("expected error, got none")
			}

			if e, a := tt.WantErr, err.Error(); !strings.Contains(a, e) {
				t.Errorf("expected %v, got %v", e, a)
			}
		})
	}
}

func TestDecryptionClientV4_CheckValidCryptographicMaterialsManager(t *testing.T) {
	_, err := materials.NewCryptographicMaterialsManager(nil)
	if err == nil {
		t.Fatal("expected error, got none")
	}
}

func TestDecryptionClientV4_EncryptionContextValidation_MockV2Object(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "hJUv7S6K2cHF64boS9ixHX0TZAjBZLT4ZpEO4XxkGnY=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("6b134eb7a353131de92faff64f594b2794e3544e31776cca26fe3bbeeffc68742d1007234f11c6670522602326868e29f37e9d2678f1614ec1a2418009b9772100929aadbed9a21a")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	cases := map[string]struct {
		storedMatDesc       string
		providedContext     map[string]string
		expectError         bool
		expectedErrorMsg    string
	}{
		"matching encryption context": {
			storedMatDesc:   `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id","custom-key":"custom-value"}`,
			providedContext: map[string]string{"custom-key": "custom-value"},
			expectError:     false,
		},
		"matching encryption context with multiple keys": {
			storedMatDesc:   `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id","key1":"value1","key2":"value2"}`,
			providedContext: map[string]string{"key1": "value1", "key2": "value2"},
			expectError:     false,
		},
		"empty encryption context matches empty stored context": {
			storedMatDesc:   `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id"}`,
			providedContext: map[string]string{},
			expectError:     false,
		},
		"mismatched encryption context value": {
			storedMatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id","custom-key":"stored-value"}`,
			providedContext:  map[string]string{"custom-key": "different-value"},
			expectError:      true,
			expectedErrorMsg: "Provided encryption context does not match information retrieved from S3",
		},
		"missing key in provided context": {
			storedMatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id","key1":"value1","key2":"value2"}`,
			providedContext:  map[string]string{"key1": "value1"},
			expectError:      true,
			expectedErrorMsg: "Provided encryption context does not match information retrieved from S3",
		},
		"extra key in provided context": {
			storedMatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id","key1":"value1"}`,
			providedContext:  map[string]string{"key1": "value1", "key2": "value2"},
			expectError:      true,
			expectedErrorMsg: "Provided encryption context does not match information retrieved from S3",
		},
		"provided context has reserved key (should be ignored in stored context)": {
			storedMatDesc:   `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id","custom-key":"custom-value"}`,
			providedContext: map[string]string{"custom-key": "custom-value"},
			expectError:     false,
		},
		"stored context missing kms_cmk_id key": {
			storedMatDesc:   `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","custom-key":"custom-value","another-key":"another-value"}`,
			providedContext: map[string]string{"custom-key": "custom-value", "another-key": "another-value"},
			expectError:     false,
		},
		"stored context missing kms_cmk_id with empty provided context": {
			storedMatDesc:   `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"}`,
			providedContext: map[string]string{},
			expectError:     false,
		},
		"invalid JSON in stored material description": {
			storedMatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","invalid-json":}`,
			providedContext:  map[string]string{"key1": "value1"},
			expectError:      true,
			expectedErrorMsg: "encryption context in stored object is not valid JSON",
		},
		"malformed JSON in stored material description": {
			storedMatDesc:    `not-json-at-all`,
			providedContext:  map[string]string{},
			expectError:      true,
			expectedErrorMsg: "encryption context in stored object is not valid JSON",
		},
		"incomplete JSON in stored material description": {
			storedMatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"`,
			providedContext:  map[string]string{},
			expectError:      true,
			expectedErrorMsg: "encryption context in stored object is not valid JSON",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tConfig := awstesting.Config()
			tHttpClient := &awstesting.MockHttpClient{
				Response: &http.Response{
					StatusCode: 200,
					Header: http.Header{
						http.CanonicalHeaderKey("x-amz-meta-x-amz-key-v2"):   []string{"PsuclPnlo2O0MQoov6kL1TBlaZG6oyNwWuAqmAgq7g8b9ZeeORi3VTMg624FU9jx"},
						http.CanonicalHeaderKey("x-amz-meta-x-amz-iv"):       []string{"dqqlq2dRVSQ5hFRb"},
						http.CanonicalHeaderKey("x-amz-meta-x-amz-matdesc"):  []string{tc.storedMatDesc},
						http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{materials.KMSContextKeyring},
						http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/GCM/NoPadding"},
					},
					Body: io.NopCloser(bytes.NewBuffer(b)),
				},
			}
			tConfig.HTTPClient = tHttpClient
			s3Client := s3.NewFromConfig(tConfig)

			client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
				clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
			})
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			input := &s3.GetObjectInput{
				Bucket: aws.String("test"),
				Key:    aws.String("test"),
			}

			// Create context with encryption context if provided
			ctx := context.Background()
			if tc.providedContext != nil {
				ctx = context.WithValue(ctx, EncryptionContext, tc.providedContext)
			}

			_, err = client.GetObject(ctx, input)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if !strings.Contains(err.Error(), tc.expectedErrorMsg) {
					t.Errorf("expected error message to contain %q, got %q", tc.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestDecryptionClientV4_EncryptionContextValidation_InvalidContextType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "hJUv7S6K2cHF64boS9ixHX0TZAjBZLT4ZpEO4XxkGnY=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	b, err := hex.DecodeString("6b134eb7a353131de92faff64f594b2794e3544e31776cca26fe3bbeeffc68742d1007234f11c6670522602326868e29f37e9d2678f1614ec1a2418009b9772100929aadbed9a21a")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				http.CanonicalHeaderKey("x-amz-meta-x-amz-key-v2"):   []string{"PsuclPnlo2O0MQoov6kL1TBlaZG6oyNwWuAqmAgq7g8b9ZeeORi3VTMg624FU9jx"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-iv"):       []string{"dqqlq2dRVSQ5hFRb"},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-matdesc"):  []string{`{"aws:x-amz-cek-alg":"AES/GCM/NoPadding","kms_cmk_id":"test-key-id"}`},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{materials.KMSContextKeyring},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/GCM/NoPadding"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := New(s3Client, cmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String("test"),
		Key:    aws.String("test"),
	}

	// Test with invalid encryption context type (string instead of map[string]string)
	ctx := context.WithValue(context.Background(), EncryptionContext, "invalid-type")

	_, err = client.GetObject(ctx, input)

	if err == nil {
		t.Fatalf("expected error but got none")
	}

	expectedErrorMsg := "encryption context provided to decrypt method is not valid JSON"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("expected error message to contain %q, got %q", expectedErrorMsg, err.Error())
	}
}

func TestValidateContentEncryptionAlgorithmAgainstCommitmentPolicy_UnrecognizedPolicy(t *testing.T) {
	algSuite := algorithms.AlgAES256GCMIV12Tag16NoKDF
	// Given: Some invalid commitment policy
	invalidPolicy := commitment.CommitmentPolicy(999)
	
	// When: Call the function under test
	err := ValidateContentEncryptionAlgorithmAgainstCommitmentPolicy(algSuite, invalidPolicy)
	
	// Then: function raises error
	if err == nil {
		t.Fatalf("expected error for unrecognized commitment policy, got nil")
	}
	
	// Then: error message contains the expected text
	expectedErrorMsg := "unknown commitment policy"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("expected error message to contain %q, got %q", expectedErrorMsg, err.Error())
	}
	
	// Then: error message includes the policy value
	expectedPolicyValue := "CommitmentPolicy(999)"
	if !strings.Contains(err.Error(), expectedPolicyValue) {
		t.Errorf("expected error message to contain %q, got %q", expectedPolicyValue, err.Error())
	}
}
