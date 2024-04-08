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

