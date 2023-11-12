package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/internal/awstesting"
	"github.com/aws/amazon-s3-encryption-client-go/materials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestNewEncryptionClientV3_NonDefaults(t *testing.T) {
	tConfig := awstesting.Config()
	tClient := s3.NewFromConfig(tConfig)

	var mcmm = mockCMM{}
	v3, _ := New(tClient, mcmm, func(clientOptions *EncryptionClientOptions) {
		clientOptions.CryptographicMaterialsManager = mcmm
		clientOptions.TempFolderPath = "/mock/path"
		clientOptions.MinFileSize = 42
	})

	if v3 == nil {
		t.Fatal("expected client to not be nil")
	}

	if !reflect.DeepEqual(mcmm, v3.Options.CryptographicMaterialsManager) {
		t.Errorf("CMM did not match provided value")
	}

	if v3.Client != tClient {
		t.Errorf("expected s3 client not be nil")
	}

	if e, a := 42, v3.Options.MinFileSize; int64(e) != a {
		t.Errorf("expected %v, got %v", e, a)
	}

	if e, a := "/mock/path", v3.Options.TempFolderPath; e != a {
		t.Errorf("expected %v, got %v", e, a)
	}
}

// keyringWithStaticTestIV is a test structure that wraps a CipherDataGeneratorWithCEKAlg and stubs in a static IV
// so that encryption tests can be guaranteed to be consistent.
type keyringWithStaticTestIV struct {
	IV []byte
	materials.Keyring
}

// isAWSFixture will avoid the warning log message when doing tests that need to mock the IV
func (k keyringWithStaticTestIV) isAWSFixture() bool {
	return true
}

func (k keyringWithStaticTestIV) OnEncrypt(ctx context.Context, materials *materials.EncryptionMaterials) (*materials.CryptographicMaterials, error) {
	cryptoMaterials, err := k.Keyring.OnEncrypt(ctx, materials)
	if err == nil {
		cryptoMaterials.IV = k.IV
	}
	return cryptoMaterials, err
}

func TestEncryptionClientV3_PutObject_KMSCONTEXT_AESGCM(t *testing.T) {
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
	kmsWithStaticIV := keyringWithStaticTestIV{
		IV: iv,
		Keyring: materials.NewKmsKeyring(kmsClient, "test-key-id", func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = false
		}),
	}

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

	cmm, err := materials.NewCryptographicMaterialsManager(kmsWithStaticIV)
	if err != nil {
		t.Fatalf("error while trying to create new CMM: %v", err)
	}
	client, _ := New(s3Client, cmm)

	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String("test-key"),
		Body: func() io.ReadSeeker {
			content, _ := hex.DecodeString("8f2c59c6dbfcacf356f3da40788cbde67ca38161a4702cbcf757af663e1c24a600001b2f500417dbf5a050f57db6737422b2ed6a44c75e0d")
			return bytes.NewReader(content)
		}(),
		Metadata: md,
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
