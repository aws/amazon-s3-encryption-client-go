//go:build s3crypto_integ

package s3crypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/awslabs/aws-sdk-go-s3-crypto"
)

func TestInteg_EncryptFixtures(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	// aws-dr-tools-functional-test
	const bucket = "aws-s3-shared-tests"
	const version = "version_2"

	cases := []struct {
		CEKAlg           string
		KEK, V1, V2, CEK string
	}{
		{
			CEKAlg: "aes_gcm",
			KEK:    "kms", V1: "AWS_SDK_TEST_ALIAS", V2: "us-west-2", CEK: "aes_gcm",
		},
		{
			CEKAlg: "aes_cbc",
			KEK:    "kms", V1: "AWS_SDK_TEST_ALIAS", V2: "us-west-2", CEK: "aes_cbc",
		},
	}

	for _, c := range cases {
		t.Run(c.CEKAlg, func(t *testing.T) {
			s3Client := s3.NewFromConfig(cfg)

			fixtures := getFixtures(t, s3Client, c.CEKAlg, bucket)
			builder, masterKey := getEncryptFixtureBuilder(t, cfg, c.KEK, c.V1, c.V2, c.CEK)

			encClient := s3crypto.NewEncryptionClientV2(s3Client, builder)

			for caseKey, plaintext := range fixtures.Plaintexts {
				_, err := encClient.PutObject(ctx, &s3.PutObjectInput{
					Bucket: aws.String(bucket),
					Key: aws.String(
						fmt.Sprintf("%s/%s/language_Go/ciphertext_test_case_%s",
							fixtures.BaseFolder, version, caseKey),
					),
					Body: bytes.NewReader(plaintext),
					Metadata: map[string]string{
						"Masterkey": masterKey,
					},
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

	const bucket = "aws-s3-shared-tests"
	const version = "version_2"

	cases := []struct {
		CEKAlg string
		Lang   string
	}{
		{CEKAlg: "aes_cbc", Lang: "Go"},
		{CEKAlg: "aes_gcm", Lang: "Go"},
		{CEKAlg: "aes_cbc", Lang: "Java"},
		{CEKAlg: "aes_gcm", Lang: "Java"},
	}

	for _, c := range cases {
		t.Run(c.CEKAlg+"-"+c.Lang, func(t *testing.T) {
			s3Client := s3.NewFromConfig(cfg)
			kmsClient := kms.NewFromConfig(cfg)
			cr := s3crypto.NewCryptoRegistry()
			s3crypto.RegisterAESCBCContentCipher(cr, s3crypto.AESCBCPadder)
			s3crypto.RegisterAESGCMContentCipher(cr)
			s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kmsClient)

			decClient, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
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

func getEncryptFixtureBuilder(t *testing.T, cfg aws.Config, kek, v1, v2, cek string) (builder s3crypto.ContentCipherBuilder, masterKey string) {
	t.Helper()

	//var handler s3crypto.CipherDataGenerator
	var handlerWithCek s3crypto.CipherDataGeneratorWithCEKAlg
	switch kek {
	case "kms":
		arn, err := getAliasInformation(cfg, v1, v2)
		if err != nil {
			t.Fatalf("failed to get fixture alias info for %s, %v", v1, err)
		}

		masterKey = base64.StdEncoding.EncodeToString([]byte(arn))
		if err != nil {
			t.Fatalf("failed to encode alias's arn %v", err)
		}

		kmsSvc := kms.NewFromConfig(cfg)
		var matDesc s3crypto.MaterialDescription
		handlerWithCek = s3crypto.NewKMSContextKeyGenerator(kmsSvc, arn, matDesc)
		//handler = s3crypto.NewKMSKeyGenerator(kmsSvc, arn)
	default:
		t.Fatalf("unknown fixture KEK, %v", kek)
	}

	switch cek {
	case "aes_gcm":
		builder = s3crypto.AESGCMContentCipherBuilderV2(handlerWithCek)
	case "aes_cbc":
		//builder = s3crypto.AESCBCContentCipherBuilder(handler, s3crypto.AESCBCPadder)
	default:
		t.Fatalf("unknown fixture CEK, %v", cek)
	}

	return builder, masterKey
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

func decryptFixtures(t *testing.T, decClient *s3crypto.DecryptionClientV2, s3Client *s3.Client,
	fixtures testFixtures, bucket, lang, version string,
) map[string][]byte {
	t.Helper()
	ctx := context.Background()

	prefix := "ciphertext_test_case_"
	lang = "language_" + lang

	ciphertexts := map[string][]byte{}
	for caseKey := range fixtures.Plaintexts {
		cipherKey := fixtures.BaseFolder + "/" + version + "/" + lang + "/" + prefix + caseKey

		// To get metadata for encryption key
		ctObj, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &cipherKey,
		})

		if err != nil {
			// TODO error?
			continue
		}

		// We don't support wrap, so skip it
		if ctObj.Metadata["X-Amz-Wrap-Alg"] != "kms" {
			continue
		}

		ctObj, err = decClient.GetObject(ctx, &s3.GetObjectInput{
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
