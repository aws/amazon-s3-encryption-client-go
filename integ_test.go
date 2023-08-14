//go:build s3crypto_integ

package s3crypto_test

import (
	"bytes"
	"context"
	"fmt"
	s3crypto "github.com/aws/amazon-s3-encryption-client-go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const version = "v3"

const defaultBucket = "s3-encryption-client-v3-go-us-west-2"
const bucketEnvvar = "BUCKET"
const defaultRegion = "us-west-2"
const regionEnvvar = "AWS_REGION"
const defaultAwsKmsAlias = "s3-encryption-client-v3-go-us-west-2"
const awsKmsAliasEnvvar = "AWS_KMS_ALIAS"

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

func TestParameterMalleabilityRemoval(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var alias = LoadAwsKmsAlias()

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var handlerWithCek s3crypto.CipherDataGeneratorWithCEKAlg
	arn, err := getAliasInformation(cfg, alias, region)
	if err != nil {
		t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
	}

	kmsClient := kms.NewFromConfig(cfg)
	var matDesc s3crypto.MaterialDescription
	handlerWithCek = s3crypto.NewKMSContextKeyGenerator(kmsClient, arn, matDesc)
	builder := s3crypto.AESGCMContentCipherBuilder(handlerWithCek)

	cr := s3crypto.NewCryptoRegistry()
	s3crypto.RegisterAESGCMContentCipher(cr)
	s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kmsClient)

	plaintext := "this is a test of the S3 Encryption Client"

	cases := []struct {
		TestName, MetadataKey, Action string
		NewMetadataKey                string
	}{
		{TestName: "content-encryption-downgrade", MetadataKey: "x-amz-cek-alg", Action: "delete"},
		{TestName: "key-wrap-downgrade-delete", MetadataKey: "x-amz-wrap-alg", Action: "delete"},
		{TestName: "key-wrap-downgrade-aes-wrap", MetadataKey: "x-amz-wrap-alg", Action: "update", NewMetadataKey: "AESWrap"},
		{TestName: "key-wrap-downgrade-aes", MetadataKey: "x-amz-wrap-alg", Action: "update", NewMetadataKey: "AES"},
	}

	for _, c := range cases {
		t.Run(c.TestName, func(t *testing.T) {
			s3Client := s3.NewFromConfig(cfg)
			encClient := s3crypto.NewEncryptionClientV3(s3Client, builder)
			decClient, err := s3crypto.NewDecryptionClientV3(s3Client, cr)
			if err != nil {
				t.Fatalf("failed to create decryption client: %v", err)
			}

			// First write some object using enc client
			_, err = encClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(c.TestName),
				Body:   bytes.NewReader([]byte(plaintext)),
			})
			if err != nil {
				t.Fatalf("failed to upload encrypted fixture, %v", err)
			}

			// Next get ciphertext using default client
			getOutput, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(c.TestName),
			})
			if err != nil {
				t.Fatalf("failed to download encrypted fixture, %v", err)
			}

			ciphertext, err := io.ReadAll(getOutput.Body)

			// Modify metadata
			metadata := getOutput.Metadata
			switch c.Action {
			case "delete":
				delete(metadata, c.MetadataKey)
			case "update":
				metadata[c.MetadataKey] = c.NewMetadataKey
			}

			// Put (with modified metadata) using default client
			_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:   aws.String(bucket),
				Key:      aws.String(c.TestName),
				Body:     bytes.NewReader(ciphertext), // does work
				Metadata: metadata,
			})
			if err != nil {
				t.Fatalf("failed to upload tampered fixture, %v", err)
			}

			// Attempt to get using dec client
			_, err = decClient.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(c.TestName),
			})
			if err == nil {
				t.Fatalf("expected error, but err is nil!, %v", err)
			}
		})

	}
}

func TestInteg_EncryptFixtures(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
	)

	var bucket = LoadBucket()

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	cases := []struct {
		CEKAlg                   string
		KEK, bucket, region, CEK string
	}{
		{
			CEKAlg: "aes_gcm",
			KEK:    "kms", bucket: "s3-encryption-client-v3-go-justplaz-us-west-2", region: "us-west-2", CEK: "aes_gcm",
		},
	}

	for _, c := range cases {
		t.Run(c.CEKAlg, func(t *testing.T) {
			s3Client := s3.NewFromConfig(cfg)

			fixtures := getFixtures(t, s3Client, c.CEKAlg, bucket)
			builder := getEncryptFixtureBuilder(t, cfg, c.KEK, c.bucket, c.region, c.CEK)

			encClient := s3crypto.NewEncryptionClientV3(s3Client, builder)

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
			cr := s3crypto.NewCryptoRegistry()
			s3crypto.RegisterAESCBCContentCipher(cr, s3crypto.AESCBCPadder)
			s3crypto.RegisterAESGCMContentCipher(cr)
			s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kmsClient)

			decClient, err := s3crypto.NewDecryptionClientV3(s3Client, cr)
			if err != nil {
				t.Fatalf("failed to create decryption client: %v", err)
			}

			fixtures := getFixtures(t, s3Client, c.CEKAlg, bucket)
			ciphertexts := decryptFixtures(t, decClient, s3Client, fixtures, bucket, c.Lang, version)

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

func getEncryptFixtureBuilder(t *testing.T, cfg aws.Config, kek, alias, region, cek string) (builder s3crypto.ContentCipherBuilder) {
	t.Helper()

	var handlerWithCek s3crypto.CipherDataGeneratorWithCEKAlg
	switch kek {
	case "kms":
		arn, err := getAliasInformation(cfg, alias, region)
		if err != nil {
			t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
		}

		kmsSvc := kms.NewFromConfig(cfg)
		var matDesc s3crypto.MaterialDescription
		handlerWithCek = s3crypto.NewKMSContextKeyGenerator(kmsSvc, arn, matDesc)
	default:
		t.Fatalf("unknown fixture KEK, %v", kek)
	}

	switch cek {
	case "aes_gcm":
		builder = s3crypto.AESGCMContentCipherBuilder(handlerWithCek)
	case "aes_cbc":
		t.Fatalf("aes cbc is not supported ")
	default:
		t.Fatalf("unknown fixture CEK, %v", cek)
	}

	return builder
}

func getAliasInformation(cfg aws.Config, alias, region string) (string, error) {
	arn := ""

	kmsConfig := cfg.Copy()
	kmsConfig.Region = region
	svc := kms.NewFromConfig(kmsConfig)

	truncated := true
	var marker *string
	for truncated {
		out, err := svc.ListAliases(context.Background(), &kms.ListAliasesInput{
			Marker: marker,
		})
		if err != nil {
			return arn, err
		}
		for _, aliasEntry := range out.Aliases {
			if *aliasEntry.AliasName == "alias/"+alias {
				return *aliasEntry.AliasArn, nil
			}
		}
		truncated = out.Truncated
		marker = out.NextMarker
	}

	return "", fmt.Errorf("kms alias %s does not exist", alias)
}

func decryptFixtures(t *testing.T, decClient *s3crypto.DecryptionClientV3, s3Client *s3.Client,
	fixtures testFixtures, bucket, lang, version string,
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
