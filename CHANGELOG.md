## 4.0.0 (2025-12-16)

### Features

* Updates to the S3 Encryption Client

See migration guide from 3.x to 4.x: [link](https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/go-v4-migration.html)

### ⚠ BREAKING CHANGES

* The S3 Encryption Client now uses key committing algorithm suites by default. 
* Removed `S3EncryptionClientV3` in favor of the upgraded `S3EncryptionClientV4`
* Updated expectations for custom implementations of the `CryptographicMaterialsManager` interface.
  * Custom implementations of the interface's `GetEncryptionMaterials` method MUST set the `AlgorithmSuite` field on the returned `EncryptionMaterials`.
    * The provided `DefaultCryptographicMaterialsManager`'s `GetEncryptionMaterials` method and the provided `NewEncryptionMaterials` method set this field from the `AlgorithmSuite` provided in the `req EncryptionMaterialsRequest`.
    * If the custom implementation wraps the provided `DefaultCryptographicMaterialsManager.GetEncryptionMaterials` method or calls the provided `NewEncryptionMaterials` method, it's likely that no code updates are required. The provided logic has been updated with this change.
  * Custom implementations of the interface's `DecryptMaterials` method MUST set the `KeyCommitment` field on the returned `CryptographicMaterials`.
    * The provided `DefaultCryptographicMaterialsManager`'s `DecryptMaterials` method and the provided `DecryptMaterials` method set this field from the `KeyCommitment` provided in the `req DecryptMaterialsRequest`.
    * If the custom implementation wraps the provided `DefaultCryptographicMaterialsManager.DecryptMaterials` method or calls the provided `NewDecryptionMaterials` method, it's likely that no code updates are required. The provided logic has been updated with this change.
* Updated expectations for custom implementations of the `Keyring` interface.
  * Custom implementations of the interface's `OnDecrypt` method MUST set the `KeyCommitment` field on the returned `CryptographicMaterials`.
    * The provided `KmsKeyring`'s `OnDecrypt` method and the provided `commonDecrypt` method set this field from the `KeyCommitment` provided in the `materials DecryptionMaterials`.
    * If the custom implementation wraps the provided `KmsKeyring.OnDecrypt` method or calls the provided `commonDecrypt` method, it's likely that no code updates are required. The provided logic has been updated with this change.

### Fixes

* Fixed an issue where nonces of invalid lengths could cause a panic during decryption.

## 3.2.0 (2025-12-16)

### Features

* Updates to the S3 Encryption Client

See migration guide from 3.x to 4.x: [link](https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/go-v4-migration.html)

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

