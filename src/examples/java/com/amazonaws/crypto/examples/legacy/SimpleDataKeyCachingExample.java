// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.legacy;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.EncryptRequest;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CryptoMaterialsCache;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.keyrings.Keyring;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * <p>
 * Encrypts a string using an AWS KMS customer master key (CMK) and data key caching
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>KMS CMK ARN: To find the Amazon Resource Name of your AWS KMS customer master key (CMK),
 *     see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class SimpleDataKeyCachingExample {

    /*
     *  The maximum number of data keys in the cache (required).
     *  When the cache is full, the oldest entry is evicted to
     *  make room for a newer one.
     */
    private static final int CAPACITY = 10;

    /*
     *  The maximum number of messages encrypted under a single data key.
     *  This value is optional, but you should configure the lowest practical value.
     */
    private static final int MAX_ENTRY_MESSAGES = 100;

    /*
     *  The time in seconds that an entry is cached (required).
     *  The cache actively removes entries that have exceeded the thresholds.
     */
    private static final int MAX_ENTRY_AGE_IN_SECONDS = 60;

    /*
     *  Example data to encrypt
     */
    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        encryptWithCaching(AwsKmsCmkId.fromString(args[0]));
    }

    static byte[] encryptWithCaching(AwsKmsCmkId kmsCmkArn) {

        // Instantiate the AWS Encryption SDK.
        final AwsCrypto crypto = new AwsCrypto();

        // Create an encryption context.
        final Map<String, String> encryptionContext = Collections.singletonMap("purpose", "test");

        // Create a keyring.
        final Keyring keyring = StandardKeyrings.awsKms(kmsCmkArn);

        // Create a cache.
        final CryptoMaterialsCache cache = new LocalCryptoMaterialsCache(CAPACITY);

        // Create a caching CMM.
        final CryptoMaterialsManager cachingCmm =
                CachingCryptoMaterialsManager.newBuilder()
                        .withKeyring(keyring)
                        .withCache(cache)
                        .withMaxAge(MAX_ENTRY_AGE_IN_SECONDS, TimeUnit.SECONDS)
                        .withMessageUseLimit(MAX_ENTRY_MESSAGES)
                        .build();

        // When the call to encrypt specifies a caching CMM,
        // the encryption operation uses the data key cache.
        return crypto.encrypt(EncryptRequest.builder()
                .cryptoMaterialsManager(cachingCmm)
                .plaintext(EXAMPLE_DATA)
                .encryptionContext(encryptionContext)
                .build()).getResult();
    }
}
