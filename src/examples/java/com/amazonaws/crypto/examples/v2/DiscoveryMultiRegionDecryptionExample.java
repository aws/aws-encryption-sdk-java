// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.regions.Region;

/**
 * <p>
 * Encrypts and then decrypts data using an AWS KMS customer master key in discovery mode.
 * Discovery mode is useful when you can't or don't want to specify a CMK on decrypt.
 * <p>
 * Arguments:
 * <ol>
 * <li>Key Name: A key identifier for the AWS KMS customer master key (CMK). For example,
 *     a key ARN or a key alias.
 *     For details, see "Key identifiers" at https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
 * <li>Partition: The partition of the AWS KMS customer master key, which is usually "aws."
 *     A partition is a group of regions. The partition is the second element in the key ARN, e.g. "arn" in "aws:aws: ..."
 *     For details, see: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arns-syntax
 * <li>Account ID: The identifier for the account of the AWS KMS customer master key.
 * </ol>
 */
public class DiscoveryMultiRegionDecryptionExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        final String keyName = args[0];
        final String partition = args[1];
        final String accountId = args[2];
        final Region discoveryMrkRegion = Region.of(args[3]);

        encryptAndDecrypt(keyName, partition, accountId, discoveryMrkRegion);
    }

    static void encryptAndDecrypt(
        final String keyName,
        final String partition,
        final String accountId,
        final Region discoveryMrkRegion
    ) {
        // 1. Instantiate the SDK
        // This builds the AwsCrypto client with
        // the RequireEncryptRequireDecrypt commitment policy,
        // which decrypts only with committing algorithm suites.
        // This is the default commitment policy
        // if you build the client with `AwsCrypto.builder().build()`
        // or `AwsCrypto.standard()`.
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();

        // 2. Instantiate an AWS KMS multi region optimized master key provider
        // in strict mode using buildStrict().
        // In this example we are using
        // two related multi region keys.
        // we will encrypt with
        // the encrypting in the encrypting region first.
        // In strict mode,
        // the AWS KMS multi region optimized master key provider encrypts
        // and decrypts only by using the key indicated
        // by key arn passed to `buildStrict`.
        // To encrypt with this master key provider,
        // use an AWS KMS key ARN to identify the CMKs.
        // In strict mode, the decrypt operation requires a key ARN.
        final AwsKmsMrkAwareMasterKeyProvider encryptingKeyProvider = AwsKmsMrkAwareMasterKeyProvider
                .builder()
                .buildStrict(keyName);

        // 3. Create an encryption context
        // Most encrypted data
        // should have an associated encryption context
        // to protect integrity.
        // This sample uses placeholder values.
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 4. Encrypt the data
        final CryptoResult<byte[], AwsKmsMrkAwareMasterKey> encryptResult = crypto
                .encryptData(encryptingKeyProvider, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // 5. Instantiate a discovery filter for decrypting.
        // This filter limits the CMKs that the ESDK can use
        // to those in the specified AWS partition and accounts.
        // This filter is not required for discovery mode,
        // but is a best practice.
        final DiscoveryFilter discoveryFilter = new DiscoveryFilter(partition, accountId);

        // 6. Instantiate an AWS KMS multi region optimized master key provider
        // for decryption in discovery mode (`buildDiscovery`)
        // with a Discovery Mrk Region
        // and with a discovery filter.
        //
        // In discovery mode, the AWS KMS multi region optimized master key provider
        // attempts to decrypt only by using AWS KMS keys indicated in the encrypted message.
        // By configuring the master key provider with a Discovery Mrk Region,
        // this master key provider will only attempt to decrypt
        // with AWS KMS multi-Region keys in the Discovery Mrk Region.
        // If the Discovery Mrk Region is not configured,
        // it is limited to the Region configured for the AWS SDK.
        final AwsKmsMrkAwareMasterKeyProvider decryptingKeyProvider = AwsKmsMrkAwareMasterKeyProvider
                .builder()
                .discoveryMrkRegion(discoveryMrkRegion)
                .buildDiscovery(discoveryFilter);

        // 7. Decrypt the data
        // Even though the message was encrypted with an AWS KMS key in one region
        // the master key provider will attempt to decrypt with the discoveryMrkRegion.
        final CryptoResult<byte[], AwsKmsMrkAwareMasterKey> decryptResult = crypto
                .decryptData(decryptingKeyProvider, ciphertext);

        // 8. Verify that the encryption context in the result contains
        // the encryption context supplied to the encryptData method.
        // Because the ESDK can add values to the encryption context,
        // don't require that the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 9. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
