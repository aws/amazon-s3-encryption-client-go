This module contains compatibility tests and integration tests for the S3EC Go.

## Generating Legacy Ciphertexts

There are some encrypted objects which the S3EC Go v3 can decrypt, but cannot encrypt.
For example, v3 does not support AES-CBC content encryption.
Naturally, it cannot encrypt using another language/runtime. 
In lieu of a more robust solution which uses CI to generate ciphertexts using e.g. S3EC Java, these ciphertexts are manually generated and kept in the S3 bucket so that the decrypt path can be validated in CI. 

**Java Code for Java Ciphertexts**

Sample code to generate Java ciphertexts follows:

```java
    @Test
    public void GenerateTestCasesGCM() {
        final String BUCKET = "s3ec-go-github-test-bucket";
        final String KMS_KEY_ID = "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Go-Github-KMS-Key";

        S3Client plaintextClient = S3Client.create();
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        ListObjectsV2Response response = v3Client.listObjectsV2(ListObjectsV2Request.builder()
                .bucket(BUCKET)
                .prefix("crypto_tests/aes_gcm").build());
        List<String> plaintexts = response.contents().stream()
                .map(S3Object::key)
                .filter(x -> x.contains("plaintext"))
                .collect(Collectors.toList());

        for (String plaintext : plaintexts) {
            ResponseBytes<GetObjectResponse> getResponse = plaintextClient.getObjectAsBytes(GetObjectRequest.builder()
                    .bucket(BUCKET)
                    .key(plaintext)
                    .build());

            String input = getResponse.asUtf8String();

            // V2 GCM
            String []tokens = plaintext.split("/");
            String testName = tokens[tokens.length - 1];
            tokens = testName.split("_");
            tokens[0] = "ciphertext";
            testName = String.join("_", tokens);

            String objectKey = "crypto_tests/aes_gcm/v2/language_Java/" + testName;
            EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
            AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                    .withEncryptionMaterialsProvider(materialsProvider)
                    .build();
            Map<String, String> encryptionContext = new HashMap<>();
            encryptionContext.put("user-metadata-key", "user-metadata-value");
            EncryptedPutObjectRequest putObjectRequest = new EncryptedPutObjectRequest(
                    BUCKET,
                    objectKey,
                    new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                    null
            ).withMaterialsDescription(encryptionContext);
            v2Client.putObject(putObjectRequest);

            // V3 GCM
            objectKey = "crypto_tests/aes_gcm/v3/language_Java/" + testName;
            KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ID);
            kmsMaterials.addDescription("user-metadata-key", "user-metadata-value-v3-to-v1");
            encryptionContext = new HashMap<>();
            encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v1");

            String finalObjectKey = objectKey;
            Map<String, String> finalEncryptionContext = encryptionContext;
            v3Client.putObject(builder -> builder
                    .bucket(BUCKET)
                    .key(finalObjectKey)
                    .overrideConfiguration(withAdditionalConfiguration(finalEncryptionContext)), RequestBody.fromString(input));
        }
        v3Client.close();
    }

    @Test
    public void GenerateTestCasesCBC() {
        final String BUCKET = "s3ec-go-github-test-bucket";
        final String KMS_KEY_ID = "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Go-Github-KMS-Key";
        final String KMS_REGION = "us-west-2";

        S3Client plaintextClient = S3Client.create();
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // The plaintexts are in the GCM bucket.
        ListObjectsV2Response response = v3Client.listObjectsV2(ListObjectsV2Request.builder()
                .bucket(BUCKET)
                .prefix("crypto_tests/aes_gcm").build());
        List<String> plaintexts = response.contents().stream()
                .map(S3Object::key)
                .filter(x -> x.contains("plaintext"))
                .collect(Collectors.toList());

        for (String plaintext : plaintexts) {
            ResponseBytes<GetObjectResponse> getResponse = plaintextClient.getObjectAsBytes(GetObjectRequest.builder()
                    .bucket(BUCKET)
                    .key(plaintext)
                    .build());

            String input = getResponse.asUtf8String();

            // V2 CBC
            String []tokens = plaintext.split("/");
            String testName = tokens[tokens.length - 1];
            tokens = testName.split("_");
            tokens[0] = "ciphertext";
            testName = String.join("_", tokens);

            String objectKey = "crypto_tests/aes_cbc/v1/language_Java/" + testName;

            // v1 Client in default (CBC) mode
            EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
            AWSKMS kmsClient = AWSKMSClientBuilder.standard()
                    .withRegion(KMS_REGION.toString())
                    .build();
            AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                    .withEncryptionMaterials(materialsProvider)
                    .withKmsClient(kmsClient)
                    .build();
            Map<String, String> encryptionContext = new HashMap<>();
            encryptionContext.put("user-metadata-key", "user-metadata-value");
            EncryptedPutObjectRequest putObjectRequest = new EncryptedPutObjectRequest(
                    BUCKET,
                    objectKey,
                    new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                    null
            ).withMaterialsDescription(encryptionContext);
            v1Client.putObject(putObjectRequest);
        }
        v3Client.close();
    }
```
