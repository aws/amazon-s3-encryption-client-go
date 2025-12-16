// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestHeaderV2SaveStrategy(t *testing.T) {
	cases := []struct {
		env      ObjectMetadata
		expected map[string]string
	}{
		{
			ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            "kms",
				CEKAlg:                "AES/GCM/NoPadding",
				TagLen:                "128",
				UnencryptedContentLen: "0",
			},
			map[string]string{
				"X-Amz-Key-V2":                     "Foo",
				"X-Amz-Iv":                         "Bar",
				"X-Amz-Matdesc":                    "{}",
				"X-Amz-Wrap-Alg":                   "kms",
				"X-Amz-Cek-Alg":                    "AES/GCM/NoPadding",
				"X-Amz-Tag-Len":                    "128",
				"X-Amz-Unencrypted-Content-Length": "0",
			},
		},
		{
			ObjectMetadata{
				CipherKey:             "Foo",
				IV:                    "Bar",
				MatDesc:               "{}",
				KeyringAlg:            "kms",
				CEKAlg:                "AES/GCM/NoPadding",
				UnencryptedContentLen: "0",
			},
			map[string]string{
				"X-Amz-Key-V2":                     "Foo",
				"X-Amz-Iv":                         "Bar",
				"X-Amz-Matdesc":                    "{}",
				"X-Amz-Wrap-Alg":                   "kms",
				"X-Amz-Cek-Alg":                    "AES/GCM/NoPadding",
				"X-Amz-Unencrypted-Content-Length": "0",
			},
		},
	}

	for _, c := range cases {
		params := &s3.PutObjectInput{}
		req := &SaveStrategyRequest{
			Envelope: &c.env,
			Input:    params,
		}
		strat := ObjectMetadataSaveStrategy{}
		err := strat.Save(context.Background(), req)
		if err != nil {
			t.Errorf("expected no error, but received %v", err)
		}

		if !reflect.DeepEqual(c.expected, params.Metadata) {
			t.Errorf("expected %v, but received %v", c.expected, params.Metadata)
		}
	}
}
