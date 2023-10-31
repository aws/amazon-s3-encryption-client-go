package s3crypto_test

import (
	"context"
	s3crypto "github.com/aws/amazon-s3-encryption-client-go"
	"reflect"
	"testing"

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
		strat := s3crypto.ObjectMetadataSaveStrategy{}
		err := strat.Save(context.Background(), req)
		if err != nil {
			t.Errorf("expected no error, but received %v", err)
		}

		if !reflect.DeepEqual(c.expected, params.Metadata) {
			t.Errorf("expected %v, but received %v", c.expected, params.Metadata)
		}
	}
}
