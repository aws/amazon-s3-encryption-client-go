package s3crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/internal/awstesting"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type mockPutObjectClient struct{}

func (m *mockPutObjectClient) PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	panic("not implemented")
}

func TestNewEncryptionClientV2(t *testing.T) {
	tClient := &mockPutObjectClient{}

	mcb := AESGCMContentCipherBuilderV2(NewKMSContextKeyGenerator(nil, "id", nil))
	v2 := NewEncryptionClientV2(tClient, mcb)
	if v2 == nil {
		t.Fatal("expected client to not be nil")
	}

	if !reflect.DeepEqual(mcb, v2.options.ContentCipherBuilder) {
		t.Errorf("content cipher builder did not match provided value")
	}

	_, ok := v2.options.SaveStrategy.(HeaderV2SaveStrategy)
	if !ok {
		t.Errorf("expected default save strategy to be s3 header strategy")
	}

	if v2.apiClient == nil {
		t.Errorf("expected s3 client not be nil")
	}

	if e, a := DefaultMinFileSize, v2.options.MinFileSize; int64(e) != a {
		t.Errorf("expected %v, got %v", e, a)
	}

	if e, a := "", v2.options.TempFolderPath; e != a {
		t.Errorf("expected %v, got %v", e, a)
	}
}

func TestNewEncryptionClientV2_NonDefaults(t *testing.T) {
	tConfig := awstesting.Config()
	tClient := s3.NewFromConfig(tConfig)

	mcb := mockCipherBuilderV2{}
	v2 := NewEncryptionClientV2(tClient, nil, func(clientOptions *EncryptionClientOptions) {
		clientOptions.ContentCipherBuilder = mcb
		clientOptions.TempFolderPath = "/mock/path"
		clientOptions.MinFileSize = 42
		clientOptions.SaveStrategy = S3SaveStrategy{}
	})

	if v2 == nil {
		t.Fatal("expected client to not be nil")
	}

	if !reflect.DeepEqual(mcb, v2.options.ContentCipherBuilder) {
		t.Errorf("content cipher builder did not match provided value")
	}

	_, ok := v2.options.SaveStrategy.(S3SaveStrategy)
	if !ok {
		t.Errorf("expected default save strategy to be s3 header strategy")
	}

	if v2.apiClient != tClient {
		t.Errorf("expected s3 client not be nil")
	}

	if e, a := 42, v2.options.MinFileSize; int64(e) != a {
		t.Errorf("expected %v, got %v", e, a)
	}

	if e, a := "/mock/path", v2.options.TempFolderPath; e != a {
		t.Errorf("expected %v, got %v", e, a)
	}
}

// cdgWithStaticTestIV is a test structure that wraps a CipherDataGeneratorWithCEKAlg and stubs in a static IV
// so that encryption tests can be guaranteed to be consistent.
type cdgWithStaticTestIV struct {
	IV []byte
	CipherDataGeneratorWithCEKAlg
}

// isAWSFixture will avoid the warning log message when doing tests that need to mock the IV
func (k cdgWithStaticTestIV) isAWSFixture() bool {
	return true
}

func (k cdgWithStaticTestIV) GenerateCipherDataWithCEKAlg(ctx context.Context, keySize, ivSize int, cekAlg string) (CipherData, error) {
	cipherData, err := k.CipherDataGeneratorWithCEKAlg.GenerateCipherDataWithCEKAlg(ctx, keySize, ivSize, cekAlg)
	if err == nil {
		cipherData.IV = k.IV
	}
	return cipherData, err
}

func TestEncryptionClientV2_PutObject_KMSCONTEXT_AESGCM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, `{"CiphertextBlob":"8gSzlk7giyfFbLPUVgoVjvQebI1827jp8lDkO+n2chsiSoegx1sjm8NdPk0Bl70I","KeyId":"test-key-id","Plaintext":"lP6AbIQTmptyb/+WQq+ubDw+w7na0T1LGSByZGuaono="}`)
	}))

	tKmsConfig := awstesting.Config()
	tKmsConfig.Region = "us-west-2"
	tKmsConfig.RetryMaxAttempts = 0
	tKmsConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	kmsClient := kms.NewFromConfig(tKmsConfig)

	var md MaterialDescription
	iv, _ := hex.DecodeString("ae325acae2bfd5b9c3d0b813")
	kmsWithStaticIV := cdgWithStaticTestIV{
		IV:                            iv,
		CipherDataGeneratorWithCEKAlg: NewKMSContextKeyGenerator(kmsClient, "test-key-id", md),
	}
	contentCipherBuilderV2 := AESGCMContentCipherBuilderV2(kmsWithStaticIV)

	tConfig := awstesting.Config()
	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			Status:     http.StatusText(200),
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
		},
	}
	tConfig.HTTPClient = tHttpClient
	s3Client := s3.NewFromConfig(tConfig)

	client := NewEncryptionClientV2(s3Client, contentCipherBuilderV2)

	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
		Body: func() io.ReadSeeker {
			content, _ := hex.DecodeString("8f2c59c6dbfcacf356f3da40788cbde67ca38161a4702cbcf757af663e1c24a600001b2f500417dbf5a050f57db6737422b2ed6a44c75e0d")
			return bytes.NewReader(content)
		}(),
	})
	if err != nil {
		t.Fatalf("PutObject failed with %v", err)
	}

	if tHttpClient.CapturedReq == nil || tHttpClient.CapturedBody == nil {
		t.Errorf("captured HTTP request/body was nil")
	}

	expected, _ := hex.DecodeString("4cd8e95a1c9b8b19640e02838b02c8c09e66250703a602956695afbc23cbb8647d51645955ab63b89733d0766f9a264adb88571b1d467b734ff72eb73d31de9a83670d59688c54ea")

	if !bytes.Equal(tHttpClient.CapturedBody, expected) {
		t.Error("encrypted bytes did not match expected")
	}

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}
