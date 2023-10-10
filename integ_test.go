//go:build s3crypto_integ

package s3crypto_test

import (
	"bytes"
	"context"
	"fmt"
	s3crypto "github.com/aws/amazon-s3-encryption-client-go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"os"
	"strings"
	"testing"
)

const version = "v3"

const defaultBucket = "s3-encryption-client-v3-go-justplaz-us-west-2"
const bucketEnvvar = "BUCKET"
const defaultRegion = "us-west-2"
const regionEnvvar = "AWS_REGION"
const defaultAwsKmsAlias = "s3-encryption-client-v3-go-justplaz-us-west-2"
const awsKmsAliasEnvvar = "AWS_KMS_ALIAS"
const awsAccountIdEnvvar = "AWS_ACCOUNT_ID"

func LoadBucket() string {
	if len(os.Getenv(bucketEnvvar)) > 0 {
		return os.Getenv(bucketEnvvar)
	} else {
		return defaultBucket
	}
}

func LoadRegion() string {
	if len(os.Getenv(regionEnvvar)) > 0 {
		return os.Getenv(regionEnvvar)
	} else {
		return defaultRegion
	}
}

func LoadAwsKmsAlias() string {
	if len(os.Getenv(awsKmsAliasEnvvar)) > 0 {
		return os.Getenv(awsKmsAliasEnvvar)
	} else {
		return defaultAwsKmsAlias
	}
}

func LoadAwsAccountId() string {
	return os.Getenv(awsAccountIdEnvvar)
}

func getAliasArn(shortAlias string, region string, accountId string) (string, error) {
	arnFormat := "arn:aws:kms:%s:%s:alias/%s"
	return fmt.Sprintf(arnFormat, region, accountId, shortAlias), nil
}

func TestInteg_EncryptFixtures(t *testing.T) {
	var region = LoadRegion()
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	var bucket = LoadBucket()
	var accountId = LoadAwsAccountId()

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
			keyring := getEncryptFixtureBuilder(t, cfg, c.KEK, c.bucket, c.region, accountId, c.CEK)

			cmm, err := s3crypto.NewCryptographicMaterialsManager(keyring)
			if err != nil {
				t.Fatalf("failed to create new CMM")
			}
			encClient, _ := s3crypto.NewS3EncryptionClientV3(s3Client, cmm)

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
		CEKAlg string
		Lang   string
	}{
		{CEKAlg: "aes_cbc", Lang: "Go"},
		{CEKAlg: "aes_gcm", Lang: "Go"},
		// TODO: Generate ciphertexts using Java client
		//{CEKAlg: "aes_cbc", Lang: "Java"},
		//{CEKAlg: "aes_gcm", Lang: "Java"},
	}

	for _, c := range cases {
		t.Run(c.CEKAlg+"-"+c.Lang, func(t *testing.T) {
			s3Client := s3.NewFromConfig(cfg)
			kmsClient := kms.NewFromConfig(cfg)
			keyringWithContext := s3crypto.NewKmsContextAnyKeyKeyring(kmsClient)
			cmm, err := s3crypto.NewCryptographicMaterialsManager(keyringWithContext)
			if err != nil {
				t.Fatalf("failed to create new CMM")
			}

			var decClient *s3crypto.S3EncryptionClientV3
			if c.CEKAlg == "aes_cbc" {
				keyring := s3crypto.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient)
				cmmCbc, err := s3crypto.NewCryptographicMaterialsManager(keyring)
				decClient, err = s3crypto.NewS3EncryptionClientV3(s3Client, cmmCbc, func(clientOptions *s3crypto.EncryptionClientOptions) {
					clientOptions.EnableLegacyModes = true
				})
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}
			} else if c.CEKAlg == "aes_gcm" {
				decClient, err = s3crypto.NewS3EncryptionClientV3(s3Client, cmm)
				if err != nil {
					t.Fatalf("failed to create decryption client: %v", err)
				}
			} else {
				t.Fatalf("unknown CEKAlg, cannot configure crypto registry: %s", c.CEKAlg)
			}

			fixtures := getFixtures(t, s3Client, c.CEKAlg, bucket)
			ciphertexts := decryptFixtures(t, decClient, fixtures, bucket, c.Lang, version)

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

func getEncryptFixtureBuilder(t *testing.T, cfg aws.Config, kek, alias, region, accountId string, cek string) (keyring s3crypto.Keyring) {
	t.Helper()

	var kmsKeyring s3crypto.Keyring
	switch kek {
	case "kms":
		arn, err := getAliasArn(alias, region, accountId)
		if err != nil {
			t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
		}

		kmsSvc := kms.NewFromConfig(cfg)
		var matDesc s3crypto.MaterialDescription
		kmsKeyring = s3crypto.NewKmsContextKeyring(kmsSvc, arn, matDesc)
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

func decryptFixtures(t *testing.T, decClient *s3crypto.S3EncryptionClientV3, fixtures testFixtures, bucket, lang, version string,
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
