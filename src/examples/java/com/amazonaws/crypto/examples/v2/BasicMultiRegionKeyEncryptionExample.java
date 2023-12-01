// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * Encrypts and then decrypts data using two related AWS KMS multi-Region keys. In this example, the
 * AWS KMS multi-Region encrypt key is in a different region than the related AWS KMS multi-Region
 * decrypt key.
 *
 * <p>This example demonstrates how you might use AWS KMS multi-Region keys and the AWS Encryption
 * SDK client-side library to encrypt data in one region, move or copy it to a different region, and
 * decrypt the data in the destination region.
 *
 * <p>Arguments: Two related AWS KMS multi-Region keys
 *
 * <ol>
 *   <li>Encrypt multi-Region key ARN
 *   <li>Decrypt multi-Region key ARN
 * </ol>
 *
 * For help finding the key ARN of your multi-Region key, see "Finding the key ID and ARN" at
 * https://docs.aws.amazon.com/kms/latest/developerguide/find-cmk-id-arn.html
 */
public class BasicMultiRegionKeyEncryptionExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        final String multiRegionEncryptKey = args[0];
        final String multiRegionDecryptKey = args[1];

        encryptAndDecrypt(multiRegionEncryptKey, multiRegionDecryptKey);
    }

    static void encryptAndDecrypt(
            final String multiRegionEncryptKey,
            final String multiRegionDecryptKey
    ) {
        // 1. Instantiate the SDK
        // This builds the AwsCrypto client with
        // the RequireEncryptRequireDecrypt commitment policy,
        // which encrypts and decrypts only with committing algorithm suites.
        // This is the default commitment policy
        // if you build the client with `AwsCrypto.builder().build()`
        // or `AwsCrypto.standard()`.
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();

        // 2. Instantiate an AWS KMS multi-Region optimized master key provider
        // in strict mode using buildStrict().
        // This example uses two related multi-Region keys.
        // In strict mode, the AWS KMS multi-Region optimized master key provider encrypts
        // and decrypts only by using the key indicated
        // by key ARN passed to `buildStrict`.
        // To encrypt with this master key provider,
        // use any valid AWS KMS key identifier to identify the CMKs.
        // In strict mode, the decrypt operation requires a key ARN.
        final AwsKmsMrkAwareMasterKeyProvider encryptingKeyProvider = AwsKmsMrkAwareMasterKeyProvider
                .builder()
                .buildStrict(multiRegionEncryptKey);

        // 3. Create an encryption context
        // Most encrypted data
        // should have an associated encryption context
        // protect its integrity.
        // This sample uses placeholder values.
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 4. Encrypt the data
        final CryptoResult<byte[], AwsKmsMrkAwareMasterKey> encryptResult = crypto.encryptData(encryptingKeyProvider, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // 5. Instantiate an AWS KMS multi-Region optimized master key provider
        // in strict mode using buildStrict().
        // This example uses two related multi-Region keys.
        // Now decrypt with a related multi-Region key in a different region.
        // In strict mode, the decrypt operation requires a key ARN.
        final AwsKmsMrkAwareMasterKeyProvider decryptKeyProvider = AwsKmsMrkAwareMasterKeyProvider
                .builder()
                .buildStrict(multiRegionDecryptKey);

        // 6. Decrypt the data with a related multi-Region key in a different region.
        final CryptoResult<byte[], AwsKmsMrkAwareMasterKey> decryptResult = crypto.decryptData(decryptKeyProvider, ciphertext);

        // 7. Verify that the encryption context in the result contains
        // the encryption context supplied to the encryptData method.
        // Because the ESDK can add values to the encryption context,
        // don't require that the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 8. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
