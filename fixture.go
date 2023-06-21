package s3crypto

// awsFixture is an unexported interface to expose whether a given fixture is an aws provided fixture, and whether that
// fixtures dependencies were constructed using aws types.
//
// This interface is used in v2 clients to warn users if they are using custom implementations of ContentCipherBuilder
// or CipherDataGenerator.
type awsFixture interface {
	isAWSFixture() bool
}
