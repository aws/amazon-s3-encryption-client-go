## 3.1.0 (2024-11-11)

### Features

* add support for GrantTokens in KMS keyring (https://github.com/aws/amazon-s3-encryption-client-go/issues/61)

## 3.0.2 (2024-09-10)

### Fixes

* allow S3EC Go to decode S3 server non-US-ASCII object metadata encoding (https://github.com/aws/amazon-s3-encryption-client-go/pull/56)

### Maintenance

* CI: Add workflow to run CI daily (https://github.com/aws/amazon-s3-encryption-client-go/pull/53)
* upgrade packages (https://github.com/aws/amazon-s3-encryption-client-go/pull/57)
* use %w for error types in string formatting (https://github.com/aws/amazon-s3-encryption-client-go/pull/54)
    
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

