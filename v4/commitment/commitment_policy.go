// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package commitment

import "fmt"

type CommitmentPolicy int

const (
	// "Forbid" writing objects encrypted with key commitment, and "allow" reading objects encrypted with key commitment.
	// FORBID_ENCRYPT_ALLOW_DECRYPT does not write objects with key commitment
	// and can read objects encrypted either with or without key commitment.
	// Keys in Instruction Files could be tampered with when reading objects without key commitment.
	// FORBID_ENCRYPT_ALLOW_DECRYPT means that this client will write objects that any v3 client can read,
	// and any v4 client (configured with either FORBID_ENCRYPT_ALLOW_DECRYPT or REQUIRE_ENCRYPT_ALLOW_DECRYPT) can read.
	// FORBID_ENCRYPT_ALLOW_DECRYPT also means that this client can read objects written by any v3 or v4 client.
	// This is the default policy for v3 clients.
	// For more information, see the developer guide:
	// https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/go-v4-migration.html
	FORBID_ENCRYPT_ALLOW_DECRYPT CommitmentPolicy = iota
	// "Require" writing objects encrypted with key commitment, and "allow" reading objects encrypted with key commitment.
	// REQUIRE_ENCRYPT_ALLOW_DECRYPT ensures that all newly written objects are protected with key commitment,
	// but can read objects encrypted either with or without key commitment.
	// Keys in Instruction Files could be tampered with when reading objects without key commitment.
	// REQUIRE_ENCRYPT_ALLOW_DECRYPT means that this client will write objects that any v3 client (from v3.2.0 onward)
	// or any v4 client can read.
	// REQUIRE_ENCRYPT_ALLOW_DECRYPT also means that this client can read objects written by any v3 or v4 client.
	// For more information, see the developer guide:
	// https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/go-v4-migration.html
	REQUIRE_ENCRYPT_ALLOW_DECRYPT
	// "Require" writing objects encrypted with key commitment, and "require" reading objects encrypted with key commitment.
	// REQUIRE_ENCRYPT_REQUIRE_DECRYPT ensures that all newly written objects are protected with key commitment
	// and that all decrypted objects are verified to have been encrypted with key commitment.
	// This prevents reading objects with keys in Instruction Files that may have been tampered with.
	// REQUIRE_ENCRYPT_REQUIRE_DECRYPT means that any v3 client (from v3.2.0 onward) or any v4 client implementation
	// can read all of the objects being written.
	// However, REQUIRE_ENCRYPT_REQUIRE_DECRYPT also means that this client can only read objects written by
	// v4 clients (configured with any REQUIRE_ENCRYPT_ALLOW_DECRYPT or REQUIRE_ENCRYPT_REQUIRE_DECRYPT).
	// This is the default policy for v4 clients.
	// For more information, see the developer guide:
	// https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/go-v4-migration.html
	REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

func (cp CommitmentPolicy) RequiresEncrypt() bool {
	switch cp {
	case REQUIRE_ENCRYPT_ALLOW_DECRYPT, REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
		return true
	default:
		return false
	}
}

func (cp CommitmentPolicy) RequiresDecrypt() bool {
	return cp == REQUIRE_ENCRYPT_REQUIRE_DECRYPT
}

func (p CommitmentPolicy) String() string {
    switch p {
    case FORBID_ENCRYPT_ALLOW_DECRYPT:
        return "FORBID_ENCRYPT_ALLOW_DECRYPT"
    case REQUIRE_ENCRYPT_ALLOW_DECRYPT:
        return "REQUIRE_ENCRYPT_ALLOW_DECRYPT"
    case REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
        return "REQUIRE_ENCRYPT_REQUIRE_DECRYPT"
    default:
        return fmt.Sprintf("CommitmentPolicy(%d)", int(p))
    }
}
