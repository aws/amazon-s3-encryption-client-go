// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/amazon-s3-encryption-client-go/v3/internal/awstesting"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestKMSKeyring_OnEncrypt_CorrectKMSRequest(t *testing.T) {
	tConfig := awstesting.Config()
	kmsKeyId := "test-key-id"
	grantTokens := []string{"test-ciphertext-blob"}

	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			// This test focuses on the KMS request correctness, so we just return an empty body
			Body: io.NopCloser(bytes.NewBuffer([]byte("{}"))),
		},
	}

	tConfig.HTTPClient = tHttpClient
	kmsClient := kms.NewFromConfig(tConfig)
	keyring := NewKmsKeyring(kmsClient, kmsKeyId)

	ctx := context.WithValue(context.Background(), "GrantTokens", grantTokens)

	encryptionMaterials := NewEncryptionMaterials()

	_, err := keyring.OnEncrypt(ctx, encryptionMaterials)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if tHttpClient.CapturedReq == nil || tHttpClient.CapturedBody == nil {
		t.Errorf("captured HTTP request/body was nil")
	}

	var capturedKmsRequest kms.GenerateDataKeyInput
	json.Unmarshal(tHttpClient.CapturedBody, &capturedKmsRequest)

	expectedRequest := kms.GenerateDataKeyInput{
		KeyId:       &kmsKeyId,
		GrantTokens: grantTokens,
		KeySpec:     types.DataKeySpecAes256,
		EncryptionContext: map[string]string{
			kmsAWSCEKContextKey: kmsDefaultEncryptionContextKey,
		},
	}

	if !reflect.DeepEqual(capturedKmsRequest, expectedRequest) {
		t.Errorf("requests sent to KMS was not the expected request.\nExpected %v\nReceived; %v", expectedRequest, capturedKmsRequest)
	}
}

func TestKMSKeyring_OnDecrypt_CorrectKMSRequest(t *testing.T) {
	tConfig := awstesting.Config()
	kmsKeyId := "test-key-id"
	dataKey := DataKey{
		EncryptedDataKey: []byte("data-key"),
		DataKeyAlgorithm: "kms+context",
	}
	grantTokens := []string{"test-ciphertext-blob"}

	tHttpClient := &awstesting.MockHttpClient{
		Response: &http.Response{
			StatusCode: 200,
			// This test focuses on the KMS request correctness, so we just return an empty body
			Body: io.NopCloser(bytes.NewBuffer([]byte("{}"))),
		},
	}

	tConfig.HTTPClient = tHttpClient
	kmsClient := kms.NewFromConfig(tConfig)
	keyring := NewKmsKeyring(kmsClient, kmsKeyId)

	ctx := context.WithValue(context.Background(), "GrantTokens", grantTokens)

	decryptionMaterials, err := NewDecryptionMaterials(DecryptMaterialsRequest{
		CipherKey:  []byte("test-cipher-key"),
		Iv:         []byte("test-iv"),
		MatDesc:    `{"aws:x-amz-cek-alg":"AES/GCM/NoPadding"}`,
		KeyringAlg: "kms+context",
		CekAlg:     kmsDefaultEncryptionContextKey,
	})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	_, err = keyring.OnDecrypt(ctx, decryptionMaterials, dataKey)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if tHttpClient.CapturedReq == nil || tHttpClient.CapturedBody == nil {
		t.Errorf("captured HTTP request/body was nil")
	}

	var capturedKmsRequest kms.DecryptInput
	json.Unmarshal(tHttpClient.CapturedBody, &capturedKmsRequest)

	expectedRequest := kms.DecryptInput{
		KeyId:          &kmsKeyId,
		GrantTokens:    grantTokens,
		CiphertextBlob: dataKey.EncryptedDataKey,
		EncryptionContext: map[string]string{
			kmsAWSCEKContextKey: kmsDefaultEncryptionContextKey,
		},
	}

	if !reflect.DeepEqual(capturedKmsRequest, expectedRequest) {
		t.Errorf("requests sent to KMS was not the expected request.\nExpected %v\nReceived; %v", expectedRequest, capturedKmsRequest)
	}
}
