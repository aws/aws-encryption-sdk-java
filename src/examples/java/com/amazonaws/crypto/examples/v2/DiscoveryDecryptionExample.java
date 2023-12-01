// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;

/**
 * <p>
 * Encrypts and then decrypts data using an AWS KMS customer master key in discovery mode.
 * Discovery mode is useful when you use an alias to identify a CMK when encrypting and the
 * underlying key ARN might vary in each AWS Region.
 * <p>
 * Arguments:
 * <ol>
 * <li>Key Name: An identifier for the AWS KMS customer master key (CMK) to use. For example,
 *     a key ARN or a key alias.
 *     For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *     key (CMK), see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * <li>Partition: The partition of the AWS KMS customer master key, which is usually "aws."
 *     A partition is a group of regions. The partition is the second element in the key ARN, e.g. "arn" in "aws:aws: ..."
 * <li>Account ID: The identifier for the account of the AWS KMS customer master key.
 * </ol>
 */
public class DiscoveryDecryptionExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        final String keyName = args[0];
        final String partition = args[1];
        final String accountId = args[2];

        encryptAndDecrypt(keyName, partition, accountId);
    }

    static void encryptAndDecrypt(final String keyName, final String partition, final String accountId) {
        // 1. Instantiate the SDK
        // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
        // which enforces that this client only encrypts using committing algorithm suites and enforces
        // that this client will only decrypt encrypted messages that were created with a committing algorithm suite.
        // This is the default commitment policy if you build the client with `AwsCrypto.builder().build()`
        // or `AwsCrypto.standard()`.
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();

        // 2. Instantiate an AWS KMS master key provider for encryption.
        //
        // In strict mode (`buildStrict`), the AWS KMS master key provider encrypts and decrypts only by using the key
        // indicated by keyName.
        final KmsMasterKeyProvider encryptingKeyProvider = KmsMasterKeyProvider.builder().buildStrict(keyName);

        // 3. Create an encryption context
        //
        // Most encrypted data should have an associated encryption context
        // to protect integrity. This sample uses placeholder values.
        //
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 4. Encrypt the data
        final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(encryptingKeyProvider, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // 5. Instantiate a discovery filter for decrypting. This filter restricts what AWS KMS CMKs the
        // AWS KMS master key provider can use to those in a particular AWS partition and account.
        // You can create a similar filter with one partition and multiple AWS accounts.
        // This example only configures the filter with one account, but more may be specified
        // as long as they exist within the same partition.
        // This filter is not required for Discovery mode, but is a best practice.
        final DiscoveryFilter discoveryFilter = new DiscoveryFilter(partition, accountId);

        // 6. Instantiate an AWS KMS master key provider for decryption in discovery mode (`buildDiscovery`) with a
        // Discovery Filter.
        //
        // In discovery mode, the AWS KMS master key provider attempts to decrypt only by using AWS KMS ARNs
        // indicated in the encrypted message.
        // By configuring the master key provider with a Discovery Filter, this master key provider
        // attempts to decrypt AWS KMS CMKs only in the configured partition and accounts.
        final KmsMasterKeyProvider decryptingKeyProvider = KmsMasterKeyProvider.builder().buildDiscovery(discoveryFilter);

        // 7. Decrypt the data
        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(decryptingKeyProvider, ciphertext);

        // 8. Verify that the encryption context in the result contains the
        // encryption context supplied to the encryptData method. Because the
        // SDK can add values to the encryption context, don't require that
        // the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 9. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
