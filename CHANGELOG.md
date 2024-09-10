### 3.0.2 (2024-09-10)

### Fixes

    * allow S3EC Go to decode S3 server non-US-ASCII object metadata encoding (#56 (https://github.com/aws/amazon-s3-encryption-client-go/issues/56)) (abd375f (https://github.com/aws/amazon-s3-encryption-client-go/commit/abd375f425be7573e25a182b6ed77790428a784e))

### Maintenance

    * CI: Add workflow to run CI daily  (#53 (https://github.com/aws/amazon-s3-encryption-client-go/issues/53)) (8a052f6 (https://github.com/aws/amazon-s3-encryption-client-go/commit/8a052f61c5940cc52018c82f94e8173822c27672))
    * upgrade packages (#57 (https://github.com/aws/amazon-s3-encryption-client-go/issues/57)) (6c36256 (https://github.com/aws/amazon-s3-encryption-client-go/commit/6c36256690ae03e46899c5416e496758c8b93369))
    * use %w for error types in string formatting (#54 (https://github.com/aws/amazon-s3-encryption-client-go/issues/54)) (50bcdc6 (https://github.com/aws/amazon-s3-encryption-client-go/commit/50bcdc63ef821fddd8fe3578fa99c082266adbec))

## 3.0.1 (2024-04-08)

### Fixes

* fix: fix legacy mode bug in both KMS keyrings (https://github.com/aws/amazon-s3-encryption-client-go/pull/48)
* fix: allow decryption of non-legacy authenticated objects when legacy modes are enabled (https://github.com/aws/amazon-s3-encryption-client-go/pull/45)

### Maintenance

* chore(ci): add README with sample Java code for generating Java ciphertexts for compatibility testing (https://github.com/aws/amazon-s3-encryption-client-go/pull/47)
* chore(ci): remove bucket lifecycle policy, add function to generate legacy ciphertexts (https://github.com/aws/amazon-s3-encryption-client-go/pull/46)

## 3.0.0 (2023-11-16)

### ⚠ BREAKING CHANGES

* Prod release for S3 EC
  * For more information see the repo's [README](https://github.com/aws/amazon-s3-encryption-client-go/blob/main/README.md)

