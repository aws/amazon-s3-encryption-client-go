/*
Package s3crypto provides encryption to S3 using KMS and AES GCM.

Keyproviders are interfaces that handle masterkeys. Masterkeys are used to encrypt and decrypt the randomly
generated cipher keys. The SDK currently uses KMS to do this. A user does not need to provide a master key
since all that information is hidden in KMS.

Modes are interfaces that handle content encryption and decryption. It is an abstraction layer that instantiates
the ciphers. If content is being encrypted we generate the key and iv of the cipher. For decryption, we use the
metadata stored either on the object or an instruction file object to decrypt the contents.

Ciphers are interfaces that handle encryption and decryption of data. This may be key wrap ciphers or content
ciphers.

Creating an S3 cryptography client

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic(err) // handle err
	}

	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)
	// Create the KeyProvider
	cmkID := "<some key ID>"
	var matdesc s3crypto.MaterialDescription
	handler := s3crypto.NewKMSContextKeyGenerator(kmsClient, cmkID, matdesc)

	// Create an encryption and decryption client
	// We need to pass the S3 client to use, any decryption that occurs will use the KMS client.
	encClient := s3crypto.NewEncryptionClientV2(sess, s3crypto.AESGCMContentCipherBuilderV2(handler))

	// Create a CryptoRegistry and register the algorithms you wish to use for decryption
	cr := s3crypto.NewCryptoRegistry()

	if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
		panic(err) // handle error
	}

	if err := s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kmsClient); err != nil {
		panic(err) // handle error
	}

	// Create a decryption client to decrypt artifacts
	decClient, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
	if err != nil {
		panic(err) // handle error
	}

Configuration of the S3 cryptography client

	handler := s3crypto.NewKMSContextKeyGenerator(kms.NewFromConfig(cfg), cmkID, s3crypto.MaterialDescription{})
	encClient, err := s3crypto.NewEncryptionClientV2(sess, s3crypto.AESGCMContentCipherBuilderV2(handler), func (o *s3crypto.EncryptionClientOptions) {
		// Save instruction files to separate objects
		o.SaveStrategy = NewS3SaveStrategy(sess, "")

		// Change instruction file suffix to .example
		o.InstructionFileSuffix = ".example"

		// Set temp folder path
		o.TempFolderPath = "/path/to/tmp/folder/"

		// Any content less than the minimum file size will use memory
		// instead of writing the contents to a temp file.
		o.MinFileSize = int64(1024 * 1024 * 1024)
	})
	if err != nil {
		panic(err) // handle error
	}

# Object Metadata SaveStrategy

The default SaveStrategy is to save metadata to an object's headers. An alternative SaveStrategy can be provided to the EncryptionClientV2.
For example, the S3SaveStrategy can be used to save the encryption metadata to an instruction file that is stored in S3
using the objects KeyName+InstructionFileSuffix. The InstructionFileSuffix defaults to .instruction. If using this strategy you will need to
configure the DecryptionClientV2 to use the matching S3LoadStrategy LoadStrategy in order to decrypt object using this save strategy.

# Custom Key Wrappers and Custom Content Encryption Algorithms

Registration of custom key wrapping or content encryption algorithms not provided by AWS is allowed by the SDK, but
security and compatibility with custom types can not be guaranteed. For example if you want to support `CustomWrap`
key wrapping algorithm and `CustomCEK` content encryption algorithm. You can use the CryptoRegistry to register these types.

	cr := s3crypto.NewCryptoRegistry()

	// Register a custom key wrap algorithm to the CryptoRegistry
	if err := cr.AddWrap("CustomWrap", NewCustomWrapEntry); err != nil {
		panic(err) // handle error
	}

	// Register a custom content encryption algorithm to the CryptoRegistry
	if err := cr.AddCEK("CustomCEK", NewCustomCEKEntry); err != nil {
		panic(err) // handle error
	}

	decClient, err := s3crypto.NewDecryptionClientV2(s3Client, cr)
	if err != nil {
		panic(err) // handle error
	}

We have now registered these new algorithms to the decryption client. When the client calls `GetObject` and sees
the wrap as `CustomWrap` then it'll use that wrap algorithm. This is also true for `CustomCEK`.

For encryption adding a custom content cipher builder and key handler will allow for encryption of custom
defined ciphers.

	// Our wrap algorithm, CustomWrap
	handler := NewCustomWrap(key, iv)
	// Our content cipher builder, NewCustomCEKContentBuilder
	encClient := s3crypto.NewEncryptionClientV2(s3Client, NewCustomCEKContentBuilder(handler))
*/
package s3crypto
