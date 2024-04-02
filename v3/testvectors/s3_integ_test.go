// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testvectors

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v3/client"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"strings"
	"testing"
	"time"
)

const version = "v3"

func getAliasArn(shortAlias string, region string, accountId string) string {
	if strings.Contains(shortAlias, "arn") {
		// shortAlias is not actually short
		return shortAlias
	}
	arnFormat := "arn:aws:kms:%s:%s:alias/%s"
	return fmt.Sprintf(arnFormat, region, accountId, shortAlias)
}

func TestInteg_EncryptFixtures(t *testing.T) {
	var region = LoadRegion()
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	var bucket = LoadBucket()
	var accountId = LoadAwsAccountId()
	var kmsAlias = LoadAwsKmsAlias()

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	cases := []struct {
		CEKAlg                   string
		KEK, bucket, region, CEK string
	}{
		{
			CEKAlg: "aes_gcm",
			KEK:    "kms", bucket: bucket, region: region, CEK: "aes_gcm",
		},
	}

	for _, c := range cases {
		t.Run(c.CEKAlg, func(t *testing.T) {
			s3Client := s3.NewFromConfig(cfg)

			fixtures := getFixtures(t, s3Client, c.CEKAlg, bucket)
			keyring := getEncryptFixtureBuilder(t, cfg, c.KEK, kmsAlias, c.region, accountId, c.CEK)

			cmm, err := materials.NewCryptographicMaterialsManager(keyring)
			if err != nil {
				t.Fatalf("failed to create new CMM")
			}
			encClient, _ := client.New(s3Client, cmm)

			for caseKey, plaintext := range fixtures.Plaintexts {
				_, err := encClient.PutObject(ctx, &s3.PutObjectInput{
					Bucket: aws.String(bucket),
					Key: aws.String(
						fmt.Sprintf("%s/%s/language_Go/ciphertext_test_case_%s",
							fixtures.BaseFolder, version, caseKey),
					),
					Body: bytes.NewReader(plaintext),
				})
				if err != nil {
					t.Fatalf("failed to upload encrypted fixture, %v", err)
				}
			}
		})
	}
}

func TestInteg_DecryptFixtures(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithLogConfigurationWarnings(true),
	)
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var bucket = LoadBucket()

	cases := []struct {
		CEKAlg  string
		Lang    string
		Version string
	}{
		{CEKAlg: "aes_cbc", Lang: "Go", Version: "v2"},
		{CEKAlg: "aes_cbc", Lang: "Java", Version: "v1"},
		{CEKAlg: "aes_gcm", Lang: "Go", Version: "v3"},
		{CEKAlg: "aes_gcm", Lang: "Java", Version: "v2"},
		{CEKAlg: "aes_gcm", Lang: "Java", Version: "v3"},
	}

	for _, c := range cases {
		t.Run(c.CEKAlg+"-"+c.Lang, func(t *testing.T) {
			s3Client := s3.NewFromConfig(cfg)
			kmsClient := kms.NewFromConfig(cfg)
			keyringWithContext := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
				options.EnableLegacyWrappingAlgorithms = false
			})
			cmm, err := materials.NewCryptographicMaterialsManager(keyringWithContext)
			if err != nil {
				t.Fatalf("failed to create new CMM")
			}

			var decClient *client.S3EncryptionClientV3
			if c.CEKAlg == "aes_cbc" {
				keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = true
				})
				cmmCbc, err := materials.NewCryptographicMaterialsManager(keyring)
				decClient, err = client.New(s3Client, cmmCbc, func(clientOptions *client.EncryptionClientOptions) {
					clientOptions.EnableLegacyUnauthenticatedModes = true
				})
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}
			} else if c.CEKAlg == "aes_gcm" {
				decClient, err = client.New(s3Client, cmm)
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}
			} else {
				t.Fatalf("unknown CEKAlg, cannot configure crypto registry: %s", c.CEKAlg)
			}

			fixtures := getFixtures(t, s3Client, c.CEKAlg, bucket)
			ciphertexts := decryptFixtures(t, decClient, fixtures, bucket, c.Lang, version)

			if len(ciphertexts) == 0 {
				t.Fatalf("expected more than 0 ciphertexts to decrypt!")
			}

			for caseKey, ciphertext := range ciphertexts {
				if e, a := len(fixtures.Plaintexts[caseKey]), len(ciphertext); e != a {
					t.Errorf("expect %v text len, got %v", e, a)
				}
				if e, a := fixtures.Plaintexts[caseKey], ciphertext; !bytes.Equal(e, a) {
					t.Errorf("expect %v text, got %v", e, a)
				}
			}
		})
	}
}

type testFixtures struct {
	BaseFolder string
	Plaintexts map[string][]byte
}

func getFixtures(t *testing.T, s3Client *s3.Client, cekAlg, bucket string) testFixtures {
	t.Helper()
	ctx := context.Background()

	prefix := "plaintext_test_case_"
	baseFolder := "crypto_tests/" + cekAlg

	out, err := s3Client.ListObjects(ctx, &s3.ListObjectsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String(baseFolder + "/" + prefix),
	})
	if err != nil {
		t.Fatalf("unable to list fixtures %v", err)
	}

	plaintexts := map[string][]byte{}
	for _, obj := range out.Contents {
		ptObj, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    obj.Key,
		})
		if err != nil {
			t.Fatalf("unable to get fixture object %s, %v", *obj.Key, err)
		}
		caseKey := strings.TrimPrefix(*obj.Key, baseFolder+"/"+prefix)
		plaintext, err := io.ReadAll(ptObj.Body)
		if err != nil {
			t.Fatalf("unable to read fixture object %s, %v", *obj.Key, err)
		}

		plaintexts[caseKey] = plaintext
	}

	return testFixtures{
		BaseFolder: baseFolder,
		Plaintexts: plaintexts,
	}
}

func getEncryptFixtureBuilder(t *testing.T, cfg aws.Config, kek, alias, region, accountId string, cek string) (keyring materials.Keyring) {
	t.Helper()

	var kmsKeyring materials.Keyring
	switch kek {
	case "kms":
		arn := getAliasArn(alias, region, accountId)

		kmsSvc := kms.NewFromConfig(cfg)
		kmsKeyring = materials.NewKmsKeyring(kmsSvc, arn, func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = false
		})
	default:
		t.Fatalf("unknown fixture KEK, %v", kek)
	}

	switch cek {
	case "aes_gcm":
		return kmsKeyring
	case "aes_cbc":
		t.Fatalf("aes cbc is not supported ")
	default:
		t.Fatalf("unknown fixture CEK, %v", cek)
	}

	return kmsKeyring
}

func decryptFixtures(t *testing.T, decClient *client.S3EncryptionClientV3, fixtures testFixtures, bucket, lang, version string,
) map[string][]byte {
	t.Helper()
	ctx := context.Background()

	prefix := "ciphertext_test_case_"
	lang = "language_" + lang

	ciphertexts := map[string][]byte{}
	for caseKey := range fixtures.Plaintexts {
		cipherKey := fixtures.BaseFolder + "/" + version + "/" + lang + "/" + prefix + caseKey
		ctObj, err := decClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &cipherKey,
		})
		if err != nil {
			t.Fatalf("failed to get encrypted object %v", err)
		}

		ciphertext, err := io.ReadAll(ctObj.Body)
		if err != nil {
			t.Fatalf("failed to read object data %v", err)
		}
		ciphertexts[caseKey] = ciphertext
	}

	return ciphertexts
}

func TestIntegS3ECHeadObject(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "single-round-trip-test" + time.Now().String()
	var plaintext = "this is some plaintext to encrypt!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	if err != nil {
		t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
	}

	var s3Client = s3.NewFromConfig(cfg)

	// Ensure fresh key
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	kmsClient := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	encryptionContext := context.WithValue(ctx, "EncryptionContext", map[string]string{"ec-key": "ec-value"})

	s3EncryptionClient, err := client.New(s3Client, cmm)
	_, err = s3EncryptionClient.PutObject(encryptionContext, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("error while encrypting: %v", err)
	}

	result, err := s3EncryptionClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}

	headResult, err := s3EncryptionClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if e, a := int64(len(plaintext)+16), headResult.ContentLength; e != a {
		t.Errorf("expect %v text, got %v", e, a)
	}

	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

func TestIntegKmsContext(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "single-round-trip-test-kms-context" + time.Now().String()
	var plaintext = "this is some plaintext to encrypt!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	if err != nil {
		t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
	}

	var s3Client = s3.NewFromConfig(cfg)

	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	kmsClient := kms.NewFromConfig(cfg)
	var matDesc materials.MaterialDescription
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	encryptionContext := context.WithValue(ctx, "EncryptionContext", map[string]string{"ec-key": "ec-value"})
	s3EncryptionClient, err := client.New(s3Client, cmm)
	_, err = s3EncryptionClient.PutObject(encryptionContext, &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Body:     bytes.NewReader([]byte(plaintext)),
		Metadata: matDesc,
	})
	if err != nil {
		t.Fatalf("error while encrypting: %v", err)
	}

	result, err := s3EncryptionClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}

	headResult, err := s3EncryptionClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if e, a := int64(len(plaintext)+16), headResult.ContentLength; e != a {
		t.Errorf("expect %v text, got %v", e, a)
	}
	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

func TestIntegKmsContextDecryptAny(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "single-round-trip-test-context-decrypt-any" + time.Now().String()
	var plaintext = "this is some plaintext to encrypt!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	if err != nil {
		t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
	}

	var s3Client = s3.NewFromConfig(cfg)

	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	kmsClient := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	encryptionContext := context.WithValue(ctx, "EncryptionContext", map[string]string{"ec-key": "ec-value"})
	s3EncryptionClient, err := client.New(s3Client, cmm)
	_, err = s3EncryptionClient.PutObject(encryptionContext, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("error while encrypting: %v", err)
	}

	// decrypt with AnyKey
	anyKeyCmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	s3EncryptionClientAnyKey, err := client.New(s3Client, anyKeyCmm)
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	result, err := s3EncryptionClientAnyKey.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}

	headResult, err := s3EncryptionClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if e, a := int64(len(plaintext)+16), headResult.ContentLength; e != a {
		t.Errorf("expect %v text, got %v", e, a)
	}
	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}
