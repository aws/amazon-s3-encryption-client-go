package s3crypto_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	s3crypto "github.com/aws/amazon-s3-encryption-client-go"
	"github.com/aws/amazon-s3-encryption-client-go/internal/awstesting"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestDecryptionClientV2_GetObject(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "hJUv7S6K2cHF64boS9ixHX0TZAjBZLT4ZpEO4XxkGnY=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	cr := s3crypto.NewCryptoRegistry()
	if err := s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kmsClient); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
		t.Fatalf("expected no error, got %v", err)
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
				http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{s3crypto.KMSContextWrap},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/GCM/NoPadding"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
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

func TestDecryptionClientV2_GetObject_V1Interop_KMS_AESCBC(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "7ItX9CTGNWWegC62RlaNu6EJ3+J9yGO7yAqDNU4CdeA=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	cr := s3crypto.NewCryptoRegistry()
	if err := s3crypto.RegisterKMSWrapWithAnyCMK(cr, kmsClient); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := s3crypto.RegisterAESCBCContentCipher(cr, s3crypto.AESCBCPadder); err != nil {
		t.Fatalf("expected no error, got %v", err)
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
				http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{s3crypto.KMSWrap},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/CBC/PKCS5Padding"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
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

func TestDecryptionClientV2_GetObject_V1Interop_KMS_AESGCM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, "Hrjrkkt/vQwMYtqvK6+MiXh3xiMvviL1Ks7w2mgsJgU=", `"}`))
	}))
	defer ts.Close()

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	cr := s3crypto.NewCryptoRegistry()
	if err := s3crypto.RegisterKMSWrapWithAnyCMK(cr, kmsClient); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
		t.Fatalf("expected no error, got %v", err)
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
				http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{s3crypto.KMSWrap},
				http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/GCM/NoPadding"},
			},
			Body: io.NopCloser(bytes.NewBuffer(b)),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
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

func TestDecryptionClientV2_GetObject_OnlyDecryptsRegisteredAlgorithms(t *testing.T) {
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
					http.CanonicalHeaderKey("x-amz-meta-x-amz-wrap-alg"): []string{s3crypto.KMSWrap},
					http.CanonicalHeaderKey("x-amz-meta-x-amz-cek-alg"):  []string{"AES/CBC/PKCS5Padding"},
				},
				Body: io.NopCloser(bytes.NewBuffer(b)),
			},
		}
	}

	cases := map[string]struct {
		Client  *s3crypto.DecryptionClientV2
		WantErr string
	}{
		"unsupported wrap": {
			Client: func() *s3crypto.DecryptionClientV2 {
				cr := s3crypto.NewCryptoRegistry()

				if err := s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kms.NewFromConfig(awstesting.Config())); err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
					t.Fatalf("expected no error, got %v", err)
				}

				tConfig := awstesting.Config()
				tConfig.HTTPClient = httpClientFactory()
				s3Client := s3.NewFromConfig(tConfig)

				client, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return client
			}(),
			WantErr: "wrap algorithm isn't supported, kms",
		},
		"unsupported cek": {
			Client: func() *s3crypto.DecryptionClientV2 {
				cr := s3crypto.NewCryptoRegistry()
				if err := s3crypto.RegisterKMSWrapWithAnyCMK(cr, kms.NewFromConfig(awstesting.Config())); err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				tConfig := awstesting.Config()
				tConfig.HTTPClient = httpClientFactory()
				s3Client := s3.NewFromConfig(tConfig)

				client, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return client
			}(),
			WantErr: "cek algorithm isn't supported, AES/CBC/PKCS5Padding",
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

func TestDecryptionClientV2_CheckValidCryptoRegistry(t *testing.T) {
	cr := s3crypto.NewCryptoRegistry()
	_, err := s3crypto.NewDecryptionClientV2(nil, cr)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if e, a := "at least one key wrapping algorithms must be provided", err.Error(); !strings.Contains(a, e) {
		t.Fatalf("expected %v, got %v", e, a)
	}
}
