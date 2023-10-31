package s3crypto_test

import (
	"context"
	"encoding/json"
	s3crypto "github.com/aws/amazon-s3-encryption-client-go"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestHeaderV2SaveStrategy(t *testing.T) {
	cases := []struct {
		env      s3crypto.ObjectMetadata
		expected map[string]string
	}{
		{
			s3crypto.ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            s3crypto.KMSKeyring,
				CEKAlg:                s3crypto.AESGCMNoPadding,
				TagLen:                "128",
				UnencryptedContentLen: "0",
			},
			map[string]string{
				"X-Amz-Key-V2":                     "Foo",
				"X-Amz-Iv":                         "Bar",
				"X-Amz-Matdesc":                    "{}",
				"X-Amz-Wrap-Alg":                   s3crypto.KMSKeyring,
				"X-Amz-Cek-Alg":                    s3crypto.AESGCMNoPadding,
				"X-Amz-Tag-Len":                    "128",
				"X-Amz-Unencrypted-Content-Length": "0",
			},
		},
		{
			s3crypto.ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            s3crypto.KMSKeyring,
				CEKAlg:                s3crypto.AESGCMNoPadding,
				UnencryptedContentLen: "0",
			},
			map[string]string{
				"X-Amz-Key-V2":                     "Foo",
				"X-Amz-Iv":                         "Bar",
				"X-Amz-Matdesc":                    "{}",
				"X-Amz-Wrap-Alg":                   s3crypto.KMSKeyring,
				"X-Amz-Cek-Alg":                    s3crypto.AESGCMNoPadding,
				"X-Amz-Unencrypted-Content-Length": "0",
			},
		},
	}

	for _, c := range cases {
		params := &s3.PutObjectInput{}
		req := &s3crypto.SaveStrategyRequest{
			Envelope: &c.env,
			Input:    params,
		}
		strat := s3crypto.HeaderV2SaveStrategy{}
		err := strat.Save(context.Background(), req)
		if err != nil {
			t.Errorf("expected no error, but received %v", err)
		}

		if !reflect.DeepEqual(c.expected, params.Metadata) {
			t.Errorf("expected %v, but received %v", c.expected, params.Metadata)
		}
	}
}

type mockPutObjectClient struct {
	captured    *s3.PutObjectInput
	response    *s3.PutObjectOutput
	responseErr error
}

func (m *mockPutObjectClient) PutObject(ctx context.Context, input *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	m.captured = input
	return m.response, m.responseErr
}

func TestS3SaveStrategy(t *testing.T) {
	cases := []struct {
		env      s3crypto.ObjectMetadata
		expected s3crypto.ObjectMetadata
	}{
		{
			s3crypto.ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            s3crypto.KMSKeyring,
				CEKAlg:                s3crypto.AESGCMNoPadding,
				TagLen:                "128",
				UnencryptedContentLen: "0",
			},
			s3crypto.ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            s3crypto.KMSKeyring,
				CEKAlg:                s3crypto.AESGCMNoPadding,
				TagLen:                "128",
				UnencryptedContentLen: "0",
			},
		},
		{
			s3crypto.ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            s3crypto.KMSKeyring,
				CEKAlg:                s3crypto.AESGCMNoPadding,
				UnencryptedContentLen: "0",
			},
			s3crypto.ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            s3crypto.KMSKeyring,
				CEKAlg:                s3crypto.AESGCMNoPadding,
				UnencryptedContentLen: "0",
			},
		},
	}

	for _, c := range cases {
		params := &s3.PutObjectInput{
			Bucket: aws.String("fooBucket"),
			Key:    aws.String("barKey"),
		}

		tClient := &mockPutObjectClient{
			response: &s3.PutObjectOutput{},
		}

		saveReq := &s3crypto.SaveStrategyRequest{
			Envelope:    &c.env,
			HTTPRequest: &http.Request{},
			Input:       params,
		}

		strat := s3crypto.S3SaveStrategy{
			APIClient: tClient,
		}
		err := strat.Save(context.Background(), saveReq)
		if err != nil {
			t.Errorf("expected no error, but received %v", err)
		}

		if tClient.captured == nil {
			t.Errorf("expected captured http request")
		}

		bodyBytes, err := io.ReadAll(tClient.captured.Body)
		if err != nil {
			t.Errorf("failed to read http body")
		}
		var actual s3crypto.ObjectMetadata
		err = json.Unmarshal(bodyBytes, &actual)
		if err != nil {
			t.Errorf("failed to unmarshal envelope")
		}

		if e, a := c.expected, actual; !reflect.DeepEqual(e, a) {
			t.Errorf("expected %v, got %v", e, a)
		}
	}
}
