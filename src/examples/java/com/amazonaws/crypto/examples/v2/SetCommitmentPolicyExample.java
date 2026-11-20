// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * <p>
 * Configures a client with a specific commitment policy, then
 * encrypts and decrypts data using an AWS KMS customer master key.
 *
 * This configuration should only be used as part of a migration from version 1.x to 2.x, or for advanced users
 * with specialized requirements. We recommend that AWS Encryption SDK users use the default commitment policy
 * whenever possible.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *    key (CMK), see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class SetCommitmentPolicyExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        final String keyArn = args[0];

        encryptAndDecrypt(keyArn);
    }

    static void encryptAndDecrypt(final String keyArn) {
        // 1. Instantiate the SDK with a specific commitment policy
        //
        // `withCommitmentPolicy(CommitmentPolicy)` configures the client with
        // a commitment policy that dictates whether the client is required to encrypt
        // using committing algorithms and whether the client must require that the messages
        // it decrypts were encrypted using committing algorithms.
        // In this example, we set the commitment policy to `ForbidEncryptAllowDecrypt`.
        // This policy enforces that the client writes using non-committing algorithms,
        // and allows decrypting of messages created with committing algorithms.
        //
        // If this value is not set, the client is configured to use our recommended default:
        // `RequireEncryptRequireDecrypt`.
        // This policy enforces that the client uses committing algorithms
        // to encrypt and enforces that the client only decrypts messages created with committing algorithms.
        // We recommend using the default whenever possible.
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                .build();

        // 2. Instantiate an AWS KMS master key provider in strict mode using buildStrict()
        // In strict mode, the AWS KMS master key provider encrypts and decrypts only by using the key
        // indicated by keyArn.
        // To encrypt and decrypt with this master key provider, use an AWS KMS key ARN to identify the CMKs.
        // In strict mode, the decrypt operation requires a key ARN.
        final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder().buildStrict(keyArn);

        // 3. Create an encryption context
        // Most encrypted data should have an associated encryption context
        // to protect integrity. This sample uses placeholder values.
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 4. Encrypt the data
        final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(keyProvider, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // 5. Decrypt the data
        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(keyProvider, ciphertext);

        // 6. Verify that the encryption context in the result contains the
        // encryption context supplied to the encryptData method. Because the
        // SDK can add values to the encryption context, don't require that
        // the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 7. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
