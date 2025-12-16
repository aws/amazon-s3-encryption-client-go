// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// specified by SDK user-agent SEP
const (
	cryptoUserAgent = "S3Cryptov4"
)

// TODO - can we get a meaningful encryption client version into the header?

// append to user agent (will be ft/s3-encrypt)
func AddS3CryptoUserAgent(options *s3.Options) {
	options.APIOptions = append(options.APIOptions, awsmiddleware.AddSDKAgentKey(awsmiddleware.FeatureMetadata, cryptoUserAgent))
}
