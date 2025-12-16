// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testvectors

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v4/algorithms"
	"github.com/aws/amazon-s3-encryption-client-go/v4/client"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v4/commitment"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"io"
	"strings"
	"testing"
	"time"
)

const version = "v4"

func getAliasArn(shortAlias string, region string, accountId string) string {
	if strings.Contains(shortAlias, "arn") {
		// shortAlias is not actually short
		return shortAlias
	}
	arnFormat := "arn:aws:kms:%s:%s:alias/%s"
	return fmt.Sprintf(arnFormat, region, accountId, shortAlias)
}

func TestInteg_EncryptFixtures_V2MessageFormat(t *testing.T) {
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
			// AES GCM implies V2 message format
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
			encClient, _ := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
				clientOptions.EnableLegacyUnauthenticatedModes = true
				clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
			})

			for caseKey, plaintext := range fixtures.Plaintexts {
				_, err := encClient.PutObject(ctx, &s3.PutObjectInput{
					Bucket: aws.String(bucket),
					Key: aws.String(
						fmt.Sprintf("%s/%s/language_Go/ciphertext_test_case_%s",
							fixtures.BaseFolder, version, caseKey),
					),
					Body: bytes.NewReader(plaintext),
				})

				// Assert correctness of encrypted object
				out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key: aws.String(
						fmt.Sprintf("%s/%s/language_Go/ciphertext_test_case_%s",
							fixtures.BaseFolder, version, caseKey),
					),
				})
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
				if _, ok := out.Metadata["x-amz-iv"]; !ok {
					t.Fatalf("expected x-amz-iv to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
				if _, ok := out.Metadata["x-amz-key-v2"]; !ok {
					t.Fatalf("expected x-amz-key-v2 to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
				if _, ok := out.Metadata["x-amz-matdesc"]; !ok {
					t.Fatalf("expected x-amz-matdesc to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
				if _, ok := out.Metadata["x-amz-wrap-alg"]; !ok {
					t.Fatalf("expected x-amz-wrap-alg to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
				if _, ok := out.Metadata["x-amz-cek-alg"]; !ok {
					t.Fatalf("expected x-amz-cek-alg to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
				if _, ok := out.Metadata["x-amz-tag-len"]; !ok {
					t.Fatalf("expected x-amz-tag-len to be present in metadata, got %v", out.Metadata)
				}

				if err != nil {
					t.Fatalf("failed to upload encrypted fixture, %v", err)
				}
			}
		})
	}
}

func TestInteg_EncryptFixtures_V3MessageFormat(t *testing.T) {
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
			// AES GCM committing implies V3 message format
			CEKAlg: "aes_gcm_committing",
			KEK:    "kms", bucket: bucket, region: region, CEK: "aes_gcm_committing",
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

				// Assert correctness of encrypted object using regular S3 client (not the encryption client)
				out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key: aws.String(
						fmt.Sprintf("%s/%s/language_Go/ciphertext_test_case_%s",
							fixtures.BaseFolder, version, caseKey),
					),
				})
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-c" MUST be present for V3 format objects.
				if _, ok := out.Metadata["x-amz-c"]; !ok {
					t.Fatalf("expected x-amz-c to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-3" MUST be present for V3 format objects.
				if _, ok := out.Metadata["x-amz-3"]; !ok {
					t.Fatalf("expected x-amz-3 to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-t" SHOULD be present for V3 format objects.
				if _, ok := out.Metadata["x-amz-t"]; !ok {
					t.Fatalf("expected x-amz-t to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-w" MUST be present for V3 format objects.
				if _, ok := out.Metadata["x-amz-w"]; !ok {
					t.Fatalf("expected x-amz-w to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-d" MUST be present for V3 format objects.
				//= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
				//= type=test
				//# The derived key commitment value MUST be set or returned from the encryption process such that it can be included in the content metadata.
				if _, ok := out.Metadata["x-amz-d"]; !ok {
					t.Fatalf("expected x-amz-d to be present in metadata, got %v", out.Metadata)
				}
				//= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
				//= type=test
				//# - The mapkey "x-amz-i" MUST be present for V3 format objects.
				if _, ok := out.Metadata["x-amz-i"]; !ok {
					t.Fatalf("expected x-amz-i to be present in metadata, got %v", out.Metadata)
				}

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
		{CEKAlg: "aes_cbc", Lang: "Go", Version: "v4"}, // v4 doesn't support CBC but that's where the files are
		{CEKAlg: "aes_gcm", Lang: "Go", Version: "v4"},
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

			var decClient *client.S3EncryptionClientV4
			if c.CEKAlg == "aes_cbc" {
				keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = true
				})
				cmmCbc, err := materials.NewCryptographicMaterialsManager(keyring)
				decClient, err = client.New(s3Client, cmmCbc, func(clientOptions *client.EncryptionClientOptions) {
					clientOptions.EnableLegacyUnauthenticatedModes = true
					clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
				})
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}
			} else if c.CEKAlg == "aes_gcm" {
				decClient, err = client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
					clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
				})
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}
			} else {
				t.Fatalf("unknown CEKAlg, cannot configure crypto registry: %s", c.CEKAlg)
			}

			fixtures := getFixtures(t, s3Client, c.CEKAlg, bucket)
			ciphertexts := decryptFixtures(t, decClient, fixtures, bucket, c.Lang, c.Version)

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
	case "aes_gcm_committing":
	case "aes_gcm":
		return kmsKeyring
	case "aes_cbc":
		t.Fatalf("aes cbc is not supported ")
	default:
		t.Fatalf("unknown fixture CEK, %v", cek)
	}

	return kmsKeyring
}

func decryptFixtures(t *testing.T, decClient *client.S3EncryptionClientV4, fixtures testFixtures, bucket, lang, version string,
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

func TestInteg_DeleteObjects_DeletesObjects(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var baseKey = "delete-objects-test-" + time.Now().Format("20060102-150405")
	var key1 = baseKey + "-object1"
	var key2 = baseKey + "-object2"
	var key3 = baseKey + "-object3"
	var plaintext1 = "Hello, S3 Encryption Client DeleteObjects test - Object 1!"
	var plaintext2 = "Hello, S3 Encryption Client DeleteObjects test - Object 2!"
	var plaintext3 = "Hello, S3 Encryption Client DeleteObjects test - Object 3!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Clean up any existing objects
	objectsToClean := []string{key1, key2, key3}
	for _, key := range objectsToClean {
		s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
	}

	// Create S3EC
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("failed to create CMM: %v", err)
	}

	s3ec, err := client.New(s3Client, cmm)
	if err != nil {
		t.Fatalf("failed to create S3EC: %v", err)
	}

	// Put multiple encrypted objects
	_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key1,
		Body:   bytes.NewReader([]byte(plaintext1)),
	})
	if err != nil {
		t.Fatalf("failed to put encrypted object 1: %v", err)
	}

	_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key2,
		Body:   bytes.NewReader([]byte(plaintext2)),
	})
	if err != nil {
		t.Fatalf("failed to put encrypted object 2: %v", err)
	}

	_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key3,
		Body:   bytes.NewReader([]byte(plaintext3)),
	})
	if err != nil {
		t.Fatalf("failed to put encrypted object 3: %v", err)
	}

	// Verify all objects exist before deletion
	for i, key := range objectsToClean {
		_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		if err != nil {
			t.Fatalf("object %d should exist before deletion: %v", i+1, err)
		}
	}

	t.Logf("✓ Verified all objects exist before deletion")

	// Test DeleteObjects - should delete all objects
	deleteInput := &s3.DeleteObjectsInput{
		Bucket: &bucket,
		Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{
				{Key: &key1},
				{Key: &key2},
				{Key: &key3},
			},
		},
	}

	//= ../specification/s3-encryption/client.md#required-api-operations
	//= type=test
	//# - DeleteObjects MUST be implemented by the S3EC.
	result, err := s3ec.DeleteObjects(ctx, deleteInput)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}

	// Verify the response structure
	if result == nil {
		t.Fatal("DeleteObjects result should not be nil")
	}

	if len(result.Deleted) != 3 {
		t.Errorf("expected 3 deleted objects, got %d", len(result.Deleted))
	}

	if len(result.Errors) > 0 {
		t.Errorf("expected no errors, got %d errors: %v", len(result.Errors), result.Errors)
	}

	// Verify all objects are deleted
	//= ../specification/s3-encryption/client.md#required-api-operations
	//= type=test
	//# - DeleteObjects MUST delete each of the given objects.
	for i, key := range objectsToClean {
		_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		if err == nil {
			t.Errorf("object %d should be deleted but still exists", i+1)
		}
	}

	// Verify all instruction files are deleted
	//= ../specification/s3-encryption/client.md#required-api-operations
	//= type=test
	//# - DeleteObjects MUST delete each of the corresponding instruction files using the default instruction file suffix.
	for i, key := range objectsToClean {
		_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    aws.String(key + ".instruction"),
		})
		if err == nil {
			t.Errorf("instruction file %d should be deleted but still exists", i+1)
		}
	}

	t.Logf("✓ DeleteObjects successfully deleted all objects")
}

func TestInteg_DeleteObject_DeletesObjectAndInstructionFile(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "delete-object-test-" + time.Now().Format("20060102-150405")
	var plaintext = "Hello, S3 Encryption Client DeleteObject test!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Clean up any existing objects
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    aws.String(key + ".instruction"),
	})

	// Create S3EC
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("failed to create CMM: %v", err)
	}

	s3ec, err := client.New(s3Client, cmm)
	if err != nil {
		t.Fatalf("failed to create S3EC: %v", err)
	}

	// Put encrypted object (this should create both the object and instruction file)
	_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("failed to put encrypted object: %v", err)
	}

	// Verify object exists before deletion
	_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("object should exist before deletion: %v", err)
	}

	// Test DeleteObject - should delete both the object and instruction file
	//= ../specification/s3-encryption/client.md#required-api-operations
	//= type=test
	//# - DeleteObject MUST be implemented by the S3EC.
	_, err = s3ec.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	// Verify both object and instruction file are deleted
	//= ../specification/s3-encryption/client.md#required-api-operations
	//= type=test
	//# - DeleteObject MUST delete the given object key.
	_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err == nil {
		t.Errorf("object should be deleted but still exists")
	}

	// Verify both object and instruction file are deleted
	//= ../specification/s3-encryption/client.md#required-api-operations
	//= type=test
	//# - DeleteObject MUST delete the associated instruction file using the default instruction file suffix.
	_, err = s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    aws.String(key + ".instruction"),
	})
	if err == nil {
		t.Errorf("instruction file should be deleted but still exists")
	}

	t.Logf("✓ DeleteObject successfully deleted both object and instruction file")
}

func TestIntegLegacyUnauthenticatedModes(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithLogConfigurationWarnings(true),
	)
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var bucket = LoadBucket()
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Test specific known objects and validate their content encryption algorithms
	testCases := []struct {
		name           string
		objectKey      string
		expectedCekAlg string
		description    string
	}{
		{
			name:           "LegacyUnauthenticated_AES_CBC",
			objectKey:      "crypto_tests/aes_cbc/v4/language_Go/ciphertext_test_case_test_one.txt",
			expectedCekAlg: "AES/CBC/PKCS5Padding",
			description:    "AES/CBC object should use legacy unauthenticated content encryption algorithm",
		},
		{
			name:           "ModernAuthenticated_AES_GCM",
			objectKey:      "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt",
			expectedCekAlg: "AES/GCM/NoPadding",
			description:    "AES/GCM object should use modern authenticated content encryption algorithm",
		},
	}

	// First validate that our test objects have the expected content encryption algorithms
	for _, tc := range testCases {
		t.Run("Validate_"+tc.name, func(t *testing.T) {
			headResult, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &tc.objectKey,
			})
			if err != nil {
				t.Skipf("Test object %s not found, skipping: %v", tc.objectKey, err)
			}

			var actualCekAlg string
			if headResult.Metadata != nil {
				if val, ok := headResult.Metadata["x-amz-cek-alg"]; ok {
					actualCekAlg = val
				}
			}

			if actualCekAlg != tc.expectedCekAlg {
				t.Errorf("Object %s has cek-alg %q, expected %q. %s", 
					tc.objectKey, actualCekAlg, tc.expectedCekAlg, tc.description)
			} else {
				t.Logf("✓ Validated: %s has expected cek-alg: %s", tc.objectKey, actualCekAlg)
			}
		})
	}

	// Get expected plaintext for test case test_one.txt
	fixtures := getFixtures(t, s3Client, "aes_cbc", bucket)
	expectedPlaintext, exists := fixtures.Plaintexts["test_one.txt"]
	if !exists {
		t.Fatal("Could not find plaintext for test case test_one.txt")
	}

	// Test legacy unauthenticated object (AES/CBC) with EnableLegacyUnauthenticatedModes = true (should succeed)
	//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
	//= type=test
	//# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
	t.Run("LegacyUnauthenticatedObject_EnabledShouldSucceed", func(t *testing.T) {
		keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = true
		})
		cmm, err := materials.NewCryptographicMaterialsManager(keyring)
		if err != nil {
			t.Fatalf("failed to create CMM: %v", err)
		}

		decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
			clientOptions.EnableLegacyUnauthenticatedModes = true
			clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
		})
		if err != nil {
			t.Fatalf("failed to create decryption client: %v", err)
		}

		legacyObjectKey := "crypto_tests/aes_cbc/v4/language_Go/ciphertext_test_case_test_one.txt"
		result, err := decClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &legacyObjectKey,
		})
		if err != nil {
			t.Fatalf("expected successful decryption of legacy unauthenticated object with EnableLegacyUnauthenticatedModes=true, but got error: %v", err)
		}

		decryptedData, err := io.ReadAll(result.Body)
		if err != nil {
			t.Fatalf("failed to read decrypted data: %v", err)
		}

		if !bytes.Equal(expectedPlaintext, decryptedData) {
			t.Errorf("decrypted data mismatch: expected %q, got %q", string(expectedPlaintext), string(decryptedData))
		}

		t.Logf("✓ Successfully decrypted legacy unauthenticated object (AES/CBC) with EnableLegacyUnauthenticatedModes=true")
	})

	// Test legacy unauthenticated object (AES/CBC) with EnableLegacyUnauthenticatedModes = false (should fail)
	//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
	//= type=test
	//# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms;
	//# it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
	//= ../specification/s3-encryption/decryption.md#legacy-decryption
	//= type=test
	//# The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites unless specifically configured to do so.
	t.Run("LegacyUnauthenticatedObject_DisabledShouldFail", func(t *testing.T) {
		keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = true
		})
		cmm, err := materials.NewCryptographicMaterialsManager(keyring)
		if err != nil {
			t.Fatalf("failed to create CMM: %v", err)
		}

		decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
			clientOptions.EnableLegacyUnauthenticatedModes = false
			clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
		})
		if err != nil {
			t.Fatalf("failed to create decryption client: %v", err)
		}

		legacyObjectKey := "crypto_tests/aes_cbc/v4/language_Go/ciphertext_test_case_test_one.txt"
		_, err = decClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &legacyObjectKey,
		})
		//= ../specification/s3-encryption/decryption.md#legacy-decryption
		//= type=test
		//# If the S3EC is not configured to enable legacy unauthenticated content decryption,
		//# the client MUST throw an exception when attempting to decrypt an object encrypted with a legacy unauthenticated algorithm suite.
		if err == nil {
			t.Fatalf("expected decryption of legacy unauthenticated object to fail when EnableLegacyUnauthenticatedModes=false, but it succeeded")
		}

		// Verify the error message indicates legacy unauthenticated modes issue
		if !strings.Contains(err.Error(), "enable legacy unauthenticated modes") && !strings.Contains(err.Error(), "AES/CBC/PKCS5Padding") {
			t.Errorf("expected error to mention legacy unauthenticated modes or AES/CBC algorithm, got: %v", err)
		}

		t.Logf("✓ Correctly failed to decrypt legacy unauthenticated object (AES/CBC) with EnableLegacyUnauthenticatedModes=false: %v", err)
	})

	// Test modern authenticated object (AES/GCM) works regardless of legacy unauthenticated modes setting
	//= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
	//= type=test
	//# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
	t.Run("ModernAuthenticatedObject_AlwaysWorks", func(t *testing.T) {
		// Get expected plaintext for modern object
		gcmFixtures := getFixtures(t, s3Client, "aes_gcm", bucket)
		gcmExpectedPlaintext, exists := gcmFixtures.Plaintexts["test_one.txt"]
		if !exists {
			t.Skip("Could not find plaintext for aes_gcm test case test_one.txt, skipping modern object test")
		}

		for _, enableLegacyUnauthenticated := range []bool{true, false} {
			t.Run(fmt.Sprintf("EnableLegacyUnauthenticated_%v", enableLegacyUnauthenticated), func(t *testing.T) {
				keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = false
				})
				cmm, err := materials.NewCryptographicMaterialsManager(keyring)
				if err != nil {
					t.Fatalf("failed to create CMM: %v", err)
				}

				decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
					clientOptions.EnableLegacyUnauthenticatedModes = enableLegacyUnauthenticated
					clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
				})
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}

				modernObjectKey := "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt"
				result, err := decClient.GetObject(ctx, &s3.GetObjectInput{
					Bucket: &bucket,
					Key:    &modernObjectKey,
				})
				if err != nil {
					t.Fatalf("modern authenticated algorithm should always work regardless of legacy unauthenticated modes setting, but got error: %v", err)
				}

				decryptedData, err := io.ReadAll(result.Body)
				if err != nil {
					t.Fatalf("failed to read decrypted data: %v", err)
				}

				if !bytes.Equal(gcmExpectedPlaintext, decryptedData) {
					t.Errorf("decrypted data mismatch: expected %q, got %q", string(gcmExpectedPlaintext), string(decryptedData))
				}

				t.Logf("✓ Modern authenticated object (AES/GCM) works correctly with EnableLegacyUnauthenticatedModes=%v", enableLegacyUnauthenticated)
			})
		}
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

func TestIntegLegacyWrappingAlgorithms(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithLogConfigurationWarnings(true),
	)
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var bucket = LoadBucket()
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Test specific known objects and validate their wrapping algorithms
	testCases := []struct {
		name           string
		objectKey      string
		expectedWrapAlg string
		cekAlg         string
		description    string
	}{
		{
			name:           "LegacyKMSKeyring_AES_CBC",
			objectKey:      "crypto_tests/aes_cbc/v4/language_Go/ciphertext_test_case_test_one.txt",
			expectedWrapAlg: "kms",
			cekAlg:         "aes_cbc",
			description:    "AES/CBC object should use legacy 'kms' wrapping algorithm",
		},
		{
			name:           "ModernKMSContextKeyring_AES_GCM",
			objectKey:      "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt",
			expectedWrapAlg: "kms+context",
			cekAlg:         "aes_gcm",
			description:    "AES/GCM object should use modern 'kms+context' wrapping algorithm",
		},
	}

	// First validate that our test objects have the expected wrapping algorithms
	for _, tc := range testCases {
		t.Run("Validate_"+tc.name, func(t *testing.T) {
			headResult, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &tc.objectKey,
			})
			if err != nil {
				t.Skipf("Test object %s not found, skipping: %v", tc.objectKey, err)
			}

			var actualWrapAlg string
			if headResult.Metadata != nil {
				if val, ok := headResult.Metadata["x-amz-wrap-alg"]; ok {
					actualWrapAlg = val
				}
			}

			if actualWrapAlg != tc.expectedWrapAlg {
				t.Errorf("Object %s has wrap-alg %q, expected %q. %s", 
					tc.objectKey, actualWrapAlg, tc.expectedWrapAlg, tc.description)
			} else {
				t.Logf("✓ Validated: %s has expected wrap-alg: %s", tc.objectKey, actualWrapAlg)
			}
		})
	}

	// Get expected plaintext for test case test_one.txt
	fixtures := getFixtures(t, s3Client, "aes_cbc", bucket)
	expectedPlaintext, exists := fixtures.Plaintexts["test_one.txt"]
	if !exists {
		t.Fatal("Could not find plaintext for test case test_one.txt")
	}

	// Test legacy object (kms) with EnableLegacyWrappingAlgorithms = true (should succeed)
	//= ../specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
	//= type=test
	//# When enabled, the S3EC MUST be able to decrypt objects encrypted with all supported wrapping algorithms (both legacy and fully supported).
	t.Run("LegacyObject_EnabledShouldSucceed", func(t *testing.T) {
		keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = true
		})
		cmm, err := materials.NewCryptographicMaterialsManager(keyring)
		if err != nil {
			t.Fatalf("failed to create CMM: %v", err)
		}

		decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
			clientOptions.EnableLegacyUnauthenticatedModes = true
			clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
		})
		if err != nil {
			t.Fatalf("failed to create decryption client: %v", err)
		}

		legacyObjectKey := "crypto_tests/aes_cbc/v4/language_Go/ciphertext_test_case_test_one.txt"
		result, err := decClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &legacyObjectKey,
		})
		if err != nil {
			t.Fatalf("expected successful decryption of legacy object with EnableLegacyWrappingAlgorithms=true, but got error: %v", err)
		}

		decryptedData, err := io.ReadAll(result.Body)
		if err != nil {
			t.Fatalf("failed to read decrypted data: %v", err)
		}

		if !bytes.Equal(expectedPlaintext, decryptedData) {
			t.Errorf("decrypted data mismatch: expected %q, got %q", string(expectedPlaintext), string(decryptedData))
		}

		t.Logf("✓ Successfully decrypted legacy object (kms wrapping algorithm) with EnableLegacyWrappingAlgorithms=true")
	})

	// Test legacy object (kms) with EnableLegacyWrappingAlgorithms = false (should fail)
	//= ../specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
	//= type=test
	//# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy wrapping algorithms;
	//# it MUST throw an exception when attempting to decrypt an object encrypted with a legacy wrapping algorithm.
	t.Run("LegacyObject_DisabledShouldFail", func(t *testing.T) {
		keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
			options.EnableLegacyWrappingAlgorithms = false
		})
		cmm, err := materials.NewCryptographicMaterialsManager(keyring)
		if err != nil {
			t.Fatalf("failed to create CMM: %v", err)
		}

		decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
			clientOptions.EnableLegacyUnauthenticatedModes = true
			clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
		})
		if err != nil {
			t.Fatalf("failed to create decryption client: %v", err)
		}

		legacyObjectKey := "crypto_tests/aes_cbc/v4/language_Go/ciphertext_test_case_test_one.txt"
		_, err = decClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &legacyObjectKey,
		})
		if err == nil {
			t.Fatalf("expected decryption of legacy object to fail when EnableLegacyWrappingAlgorithms=false, but it succeeded")
		}

		// Verify the error message indicates legacy wrapping algorithm issue
		if !strings.Contains(err.Error(), "legacyWrappingAlgorithms") && !strings.Contains(err.Error(), "did not match an expected algorithm") {
			t.Errorf("expected error to mention legacyWrappingAlgorithms or algorithm mismatch, got: %v", err)
		}

		t.Logf("✓ Correctly failed to decrypt legacy object (kms wrapping algorithm) with EnableLegacyWrappingAlgorithms=false: %v", err)
	})

	// Test modern object (kms+context) works regardless of legacy setting
	//= ../specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
	//= type=test
	//# When enabled, the S3EC MUST be able to decrypt objects encrypted with all supported wrapping algorithms (both legacy and fully supported).
	t.Run("ModernObject_AlwaysWorks", func(t *testing.T) {
		// Get expected plaintext for modern object
		gcmFixtures := getFixtures(t, s3Client, "aes_gcm", bucket)
		gcmExpectedPlaintext, exists := gcmFixtures.Plaintexts["test_one.txt"]
		if !exists {
			t.Skip("Could not find plaintext for aes_gcm test case test_one.txt, skipping modern object test")
		}

		for _, enableLegacy := range []bool{true, false} {
			t.Run(fmt.Sprintf("EnableLegacy_%v", enableLegacy), func(t *testing.T) {
				keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
					options.EnableLegacyWrappingAlgorithms = enableLegacy
				})
				cmm, err := materials.NewCryptographicMaterialsManager(keyring)
				if err != nil {
					t.Fatalf("failed to create CMM: %v", err)
				}

				decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
					clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
				})
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}

				modernObjectKey := "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt"
				result, err := decClient.GetObject(ctx, &s3.GetObjectInput{
					Bucket: &bucket,
					Key:    &modernObjectKey,
				})
				if err != nil {
					t.Fatalf("modern algorithm should always work regardless of legacy setting, but got error: %v", err)
				}

				decryptedData, err := io.ReadAll(result.Body)
				if err != nil {
					t.Fatalf("failed to read decrypted data: %v", err)
				}

				if !bytes.Equal(gcmExpectedPlaintext, decryptedData) {
					t.Errorf("decrypted data mismatch: expected %q, got %q", string(gcmExpectedPlaintext), string(decryptedData))
				}

				t.Logf("✓ Modern object (kms+context wrapping algorithm) works correctly with EnableLegacyWrappingAlgorithms=%v", enableLegacy)
			})
		}
	})
}

//= ../specification/s3-encryption/client.md#required-api-operations
//= type=test
//# - GetObject MUST be implemented by the S3EC.
//# - GetObject MUST decrypt data received from the S3 server and return it as plaintext.
func TestInteg_GetObject_BasicDecryption(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "basic-getobject-test-" + time.Now().Format("20060102-150405")
	var plaintext = "Hello, S3 Encryption Client GetObject test!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Clean up any existing object
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	// Create S3EC and encrypt an object
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("failed to create CMM: %v", err)
	}

	s3ec, err := client.New(s3Client, cmm)
	if err != nil {
		t.Fatalf("failed to create S3EC: %v", err)
	}

	// Put encrypted object
	_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("failed to put encrypted object: %v", err)
	}
	
	// Loose assertion that the object was encrypted by checking that its body does not match the plaintext
	rawResult, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("failed to get raw object: %v", err)
	}

	rawData, err := io.ReadAll(rawResult.Body)
	if err != nil {
		t.Fatalf("failed to read raw object data: %v", err)
	}

	if string(rawData) == plaintext {
		t.Errorf("object was not encrypted: raw data matches plaintext")
	}

	// Test GetObject - should decrypt and return plaintext
	result, err := s3ec.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}

	decryptedData, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted data: %v", err)
	}

	if string(decryptedData) != plaintext {
		t.Errorf("GetObject decryption failed: expected %q, got %q", plaintext, string(decryptedData))
	}

	t.Logf("✓ GetObject successfully decrypted data and returned plaintext")

	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

//= ../specification/s3-encryption/client.md#required-api-operations
//= type=test
//# - PutObject MUST be implemented by the S3EC.
//# - PutObject MUST encrypt its input data before it is uploaded to S3.
func TestInteg_PutObject_BasicEncryption(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "basic-putobject-test-" + time.Now().Format("20060102-150405")
	var plaintext = "Hello, S3 Encryption Client PutObject test!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Clean up any existing object
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	// Create S3EC
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("failed to create CMM: %v", err)
	}

	s3ec, err := client.New(s3Client, cmm)
	if err != nil {
		t.Fatalf("failed to create S3EC: %v", err)
	}

	// Test PutObject - should encrypt input data before uploading
	_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Loose assertion that the object was encrypted by checking that its body does not match the plaintext
	rawResult, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("failed to get raw object: %v", err)
	}

	rawData, err := io.ReadAll(rawResult.Body)
	if err != nil {
		t.Fatalf("failed to read raw object data: %v", err)
	}

	if string(rawData) == plaintext {
		t.Errorf("object was not encrypted: raw data matches plaintext")
	}

	// Verify encryption metadata is present
	if rawResult.Metadata == nil {
		t.Fatal("expected encryption metadata to be present")
	}

	expectedMetadataKeys := []string{"x-amz-c", "x-amz-3", "x-amz-w", "x-amz-d", "x-amz-i"}
	for _, key := range expectedMetadataKeys {
		if _, exists := rawResult.Metadata[key]; !exists {
			t.Errorf("expected encryption metadata key %s to be present", key)
		}
	}

	// Verify we can decrypt it back to the original plaintext
	decryptResult, err := s3ec.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("failed to decrypt object: %v", err)
	}

	decryptedData, err := io.ReadAll(decryptResult.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted data: %v", err)
	}

	if string(decryptedData) != plaintext {
		t.Errorf("decryption verification failed: expected %q, got %q", plaintext, string(decryptedData))
	}

	t.Logf("✓ PutObject successfully encrypted input data before uploading to S3")

	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

//= ../specification/s3-encryption/decryption.md#key-commitment
//= type=test
//# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
func TestInteg_ValidateAlgorithmSuiteAgainstCommitmentPolicy(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithLogConfigurationWarnings(true),
	)
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var bucket = LoadBucket()
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Matrix of [V3 object, V2 object] x [commitment policies] = 6 test cases
	cases := []struct {
		name             string
		objectKey        string
		objectType       string
		commitmentPolicy commitment.CommitmentPolicy
		expectError      bool
		errorContains    string
	}{
		{
			name:             "V3_object_with_FORBID_ENCRYPT_ALLOW_DECRYPT",
			objectKey:        "crypto_tests/aes_gcm_committing/v4/language_Go/ciphertext_test_case_test_one.txt",
			objectType:       "V3",
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			expectError:      false,
		},
		{
			name:             "V3_object_with_REQUIRE_ENCRYPT_ALLOW_DECRYPT",
			objectKey:        "crypto_tests/aes_gcm_committing/v4/language_Go/ciphertext_test_case_test_one.txt",
			objectType:       "V3",
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
			expectError:      false,
		},
		{
			name:             "V3_object_with_REQUIRE_ENCRYPT_REQUIRE_DECRYPT",
			objectKey:        "crypto_tests/aes_gcm_committing/v4/language_Go/ciphertext_test_case_test_one.txt",
			objectType:       "V3",
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			expectError:      false,
		},
		{
			name:             "V2_object_with_FORBID_ENCRYPT_ALLOW_DECRYPT",
			objectKey:        "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt",
			objectType:       "V2",
			commitmentPolicy: commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			expectError:      false,
		},
		{
			name:             "V2_object_with_REQUIRE_ENCRYPT_ALLOW_DECRYPT",
			objectKey:        "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt",
			objectType:       "V2",
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
			expectError:      false,
		},
		// Only expected failure case on decryption, where a non-committing object is
		// attempted to be decrypted under a commitment policy that requires commitment.
		{
			name:             "V2_object_with_REQUIRE_ENCRYPT_REQUIRE_DECRYPT",
			objectKey:        "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt",
			objectType:       "V2",
			commitmentPolicy: commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			expectError:      true,
			errorContains:    "object's content encryption algorithm is not valid for the selected commitment policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
				options.EnableLegacyWrappingAlgorithms = false
			})
			cmm, err := materials.NewCryptographicMaterialsManager(keyring)
			if err != nil {
				t.Fatalf("failed to create CMM: %v", err)
			}

			decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
				clientOptions.CommitmentPolicy = tc.commitmentPolicy
			})
			if err != nil {
				t.Fatalf("expected no error during client creation, got %v", err)
			}

			_, err = decClient.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &tc.objectKey,
			})

			//= ../specification/s3-encryption/decryption.md#key-commitment
			//= type=test
			//# If the commitment policy requires decryption using a committing algorithm suite,
			//# and the algorithm suite associated with the object does not support key commitment,
			//# then the S3EC MUST throw an exception.
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tc.errorContains, err.Error())
				} else {
					t.Logf("✓ Expected error during GetObject: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				t.Logf("✓ Successfully decrypted %s object with %s policy", tc.objectType, tc.commitmentPolicy)
			}
		})
	}
}

func TestInteg_AlgorithmSuiteMessageFormatCompatibility(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var baseKey = "algorithm-suite-message-format-test-" + time.Now().Format("20060102-150405")
	var plaintext = "Hello, S3 Encryption Client Algorithm Suite Message Format test!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	testCases := []struct {
		name                string
		algorithmSuite      string
		commitmentPolicy    commitment.CommitmentPolicy
		enableLegacyModes   bool
		enableLegacyWrap    bool
		expectedFormat      string
		expectedHeaders     []string
	}{
		//= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
		//= type=test
		//# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
		{
			name:                "ALG_AES_256_GCM_IV12_TAG16_NO_KDF_V2_Format",
			algorithmSuite:      "AES256GCMIV12Tag16NoKDF",
			commitmentPolicy:    commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			enableLegacyModes:   false,
			enableLegacyWrap:    false,
			expectedFormat:      "V2",
			expectedHeaders:     []string{"x-amz-iv", "x-amz-key-v2", "x-amz-matdesc", "x-amz-wrap-alg", "x-amz-cek-alg", "x-amz-tag-len"},
		},
		//= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
		//= type=test
		//# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
		{
			name:                "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_V3_Format",
			algorithmSuite:      "AES256GCMHkdfSha512CommitKey",
			commitmentPolicy:    commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			enableLegacyModes:   false,
			enableLegacyWrap:    false,
			expectedFormat:      "V3",
			expectedHeaders:     []string{"x-amz-c", "x-amz-3", "x-amz-t", "x-amz-w", "x-amz-d", "x-amz-i"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			key := baseKey + "-" + tc.algorithmSuite

			// Clean up any existing object
			s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})

			// Create keyring with appropriate legacy settings
			keyring := materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
				options.EnableLegacyWrappingAlgorithms = tc.enableLegacyWrap
			})

			cmm, err := materials.NewCryptographicMaterialsManager(keyring)
			if err != nil {
				t.Fatalf("failed to create CMM: %v", err)
			}

			// Create S3EC with specific configuration
			var s3ec *client.S3EncryptionClientV4
			if tc.algorithmSuite == "AES256GCMHkdfSha512CommitKey" {
				// For committing algorithm suite, use default client (which uses committing by default)
				s3ec, err = client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
					clientOptions.EnableLegacyUnauthenticatedModes = tc.enableLegacyModes
					clientOptions.CommitmentPolicy = tc.commitmentPolicy
					// Don't override algorithm suite - let it use the default committing algorithm
				})
			} else {
				// For non-committing algorithm suites, explicitly set them
				s3ec, err = client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
					clientOptions.EnableLegacyUnauthenticatedModes = tc.enableLegacyModes
					clientOptions.CommitmentPolicy = tc.commitmentPolicy
					
					// Configure the specific algorithm suite
					switch tc.algorithmSuite {
					case "AES256CBCIV16NoKDF":
						clientOptions.EncryptionAlgorithmSuite = algorithms.AlgAES256CBCIV16NoKDF
					case "AES256GCMIV12Tag16NoKDF":
						clientOptions.EncryptionAlgorithmSuite = algorithms.AlgAES256GCMIV12Tag16NoKDF
					default:
						t.Fatalf("unknown algorithm suite: %s", tc.algorithmSuite)
					}
				})
			}
			if err != nil {
				t.Fatalf("failed to create S3EC: %v", err)
			}

			// Encrypt object with configured algorithm suite
			_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
				Body:   bytes.NewReader([]byte(plaintext)),
			})
			if err != nil {
				t.Fatalf("failed to put encrypted object: %v", err)
			}

			// Get object metadata using regular S3 client to inspect message format headers
			result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			if err != nil {
				t.Fatalf("failed to get encrypted object metadata: %v", err)
			}

			// Verify the expected message format headers are present
			if result.Metadata == nil {
				t.Fatalf("expected metadata to be present for %s format", tc.expectedFormat)
			}

			t.Logf("Testing %s algorithm suite for %s message format", tc.algorithmSuite, tc.expectedFormat)
			t.Logf("Object metadata: %v", result.Metadata)

			// Assert all expected headers for the message format are present
			for _, expectedHeader := range tc.expectedHeaders {
				if _, exists := result.Metadata[expectedHeader]; !exists {
					t.Errorf("expected %s format header '%s' to be present for algorithm suite %s, but it was missing", 
						tc.expectedFormat, expectedHeader, tc.algorithmSuite)
				} else {
					t.Logf("✓ Found expected %s format header: %s", tc.expectedFormat, expectedHeader)
				}
			}

			// Verify that headers from other message formats are NOT present
			var unexpectedHeaders []string
			if tc.expectedFormat == "V2" {
				// V2 format should not have V3 headers
				unexpectedHeaders = []string{"x-amz-c", "x-amz-3", "x-amz-w", "x-amz-d", "x-amz-i"}
			} else if tc.expectedFormat == "V3" {
				// V3 format should not have V2 headers
				unexpectedHeaders = []string{"x-amz-iv", "x-amz-key-v2", "x-amz-tag-len"}
			}

			for _, unexpectedHeader := range unexpectedHeaders {
				if _, exists := result.Metadata[unexpectedHeader]; exists {
					t.Errorf("unexpected header '%s' found for %s format with algorithm suite %s", 
						unexpectedHeader, tc.expectedFormat, tc.algorithmSuite)
				}
			}

			t.Logf("✓ Algorithm suite %s correctly uses %s message format", tc.algorithmSuite, tc.expectedFormat)

			// Decrypt sanity check - verify we can decrypt the object back to original plaintext
			decryptResult, err := s3ec.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
			if err != nil {
				t.Fatalf("failed to decrypt object with algorithm suite %s: %v", tc.algorithmSuite, err)
			}

			decryptedData, err := io.ReadAll(decryptResult.Body)
			if err != nil {
				t.Fatalf("failed to read decrypted data for algorithm suite %s: %v", tc.algorithmSuite, err)
			}

			if string(decryptedData) != plaintext {
				t.Errorf("decrypt sanity check failed for algorithm suite %s: expected %q, got %q", 
					tc.algorithmSuite, plaintext, string(decryptedData))
			} else {
				t.Logf("✓ Decrypt sanity check passed for algorithm suite %s: successfully decrypted %d bytes", 
					tc.algorithmSuite, len(decryptedData))
			}

			// Cleanup
			s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
		})
	}
}

func TestInteg_CommitmentPolicyBehavior(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var baseKey = "commitment-policy-test-" + time.Now().Format("20060102-150405")
	var plaintext = "Hello, S3 Encryption Client Commitment Policy test!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	cases := []struct {
		name                    string
		commitmentPolicy        commitment.CommitmentPolicy
		algorithmSuite          *algorithms.AlgorithmSuite
		expectEncryptError      bool
		expectDecryptError      bool
		encryptErrorContains    string
		decryptErrorContains    string
	}{
		//= ../specification/s3-encryption/key-commitment.md#commitment-policy
		//= type=test
		//# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
		{
			name:                    "FORBID_with_committing_algorithm",
			commitmentPolicy:        commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			algorithmSuite:          algorithms.AlgAES256GCMHkdfSha512CommitKey,
			expectEncryptError:      true,
			expectDecryptError:      false,
			encryptErrorContains:    "does not allow committing algorithm suites",
		},
		//= ../specification/s3-encryption/key-commitment.md#commitment-policy
		//= type=test
		//# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
		{
			name:                    "FORBID_with_non_committing_algorithm",
			commitmentPolicy:        commitment.FORBID_ENCRYPT_ALLOW_DECRYPT,
			algorithmSuite:          algorithms.AlgAES256GCMIV12Tag16NoKDF,
			expectEncryptError:      false,
			expectDecryptError:      false,
		},
		//= ../specification/s3-encryption/key-commitment.md#commitment-policy
		//= type=test
		//# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
		{
			name:                    "REQUIRE_ENCRYPT_ALLOW_DECRYPT_with_committing_algorithm",
			commitmentPolicy:        commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
			algorithmSuite:          algorithms.AlgAES256GCMHkdfSha512CommitKey,
			expectEncryptError:      false,
			expectDecryptError:      false,
		},
		//= ../specification/s3-encryption/key-commitment.md#commitment-policy
		//= type=test
		//# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
		{
			name:                    "REQUIRE_ENCRYPT_ALLOW_DECRYPT_with_non_committing_algorithm",
			commitmentPolicy:        commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT,
			algorithmSuite:          algorithms.AlgAES256GCMIV12Tag16NoKDF,
			expectEncryptError:      true,
			expectDecryptError:      false,
			encryptErrorContains:    "requires committing algorithm suites",
		},
		//= ../specification/s3-encryption/key-commitment.md#commitment-policy
		//= type=test
		//# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
		{
			name:                    "REQUIRE_ENCRYPT_REQUIRE_DECRYPT_with_committing_algorithm",
			commitmentPolicy:        commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
			algorithmSuite:          algorithms.AlgAES256GCMHkdfSha512CommitKey,
			expectEncryptError:      false,
			expectDecryptError:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := baseKey + "-" + tc.name

			// Clean up any existing object
			s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})

			keyring := materials.NewKmsKeyring(kmsClient, arn, func(options *materials.KeyringOptions) {
				options.EnableLegacyWrappingAlgorithms = false
			})
			cmm, err := materials.NewCryptographicMaterialsManager(keyring)
			if err != nil {
				t.Fatalf("failed to create CMM: %v", err)
			}

			// Test encryption behavior
			s3ec, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
				clientOptions.CommitmentPolicy = tc.commitmentPolicy
				clientOptions.EncryptionAlgorithmSuite = tc.algorithmSuite
			})
			if err != nil {
				if tc.expectEncryptError && tc.encryptErrorContains != "" && strings.Contains(err.Error(), tc.encryptErrorContains) {
					t.Logf("✓ Expected error during client creation for encryption: %v", err)
					return // Expected error during client creation
				}
				t.Fatalf("expected no error during client creation, got %v", err)
			}

			_, err = s3ec.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
				Body:   bytes.NewReader([]byte(plaintext)),
			})

			if tc.expectEncryptError {
				if err == nil {
					t.Fatalf("expected encryption error but got none")
				}
				if tc.encryptErrorContains != "" && !strings.Contains(err.Error(), tc.encryptErrorContains) {
					t.Errorf("expected encryption error to contain %q, got %q", tc.encryptErrorContains, err.Error())
				} else {
					t.Logf("✓ Expected encryption error: %v", err)
				}
				return // Don't test decryption if encryption failed
			} else {
				if err != nil {
					t.Fatalf("expected no encryption error, got %v", err)
				}
				t.Logf("✓ Successfully encrypted with %s policy and %s algorithm", tc.commitmentPolicy, tc.algorithmSuite.CipherName())
			}

			// Test decryption behavior - create a new client for decryption
			decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
				clientOptions.CommitmentPolicy = tc.commitmentPolicy
			})
			if err != nil {
				t.Fatalf("failed to create decryption client: %v", err)
			}

			_, err = decClient.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})

			if tc.expectDecryptError {
				if err == nil {
					t.Fatalf("expected decryption error but got none")
				}
				if tc.decryptErrorContains != "" && !strings.Contains(err.Error(), tc.decryptErrorContains) {
					t.Errorf("expected decryption error to contain %q, got %q", tc.decryptErrorContains, err.Error())
				} else {
					t.Logf("✓ Expected decryption error: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no decryption error, got %v", err)
				}
				t.Logf("✓ Successfully decrypted with %s policy", tc.commitmentPolicy)
			}

			// Cleanup
			s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &key,
			})
		})
	}
}


//= ../specification/s3-encryption/key-commitment.md#commitment-policy
//= type=test
//# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
func TestInteg_RequireEncryptRequireDecrypt_RejectsNonCommittingObjects(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithLogConfigurationWarnings(true),
	)
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var bucket = LoadBucket()
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Test that REQUIRE_ENCRYPT_REQUIRE_DECRYPT policy rejects decryption of non-committing objects
	keyring := materials.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Fatalf("failed to create CMM: %v", err)
	}

	decClient, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
	})
	if err != nil {
		t.Fatalf("failed to create decryption client: %v", err)
	}

	// Try to decrypt a non-committing object (V2 format, AES/GCM without commitment)
	nonCommittingObjectKey := "crypto_tests/aes_gcm/v4/language_Go/ciphertext_test_case_test_one.txt"
	_, err = decClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &nonCommittingObjectKey,
	})

	if err == nil {
		t.Fatalf("expected decryption error when trying to decrypt non-committing object with REQUIRE_ENCRYPT_REQUIRE_DECRYPT policy, but got none")
	}

	if !strings.Contains(err.Error(), "object's content encryption algorithm is not valid for the selected commitment policy") {
		t.Errorf("expected error to contain commitment policy validation message, got: %v", err)
	}

	t.Logf("✓ REQUIRE_ENCRYPT_REQUIRE_DECRYPT policy correctly rejected decryption of non-committing object: %v", err)
}