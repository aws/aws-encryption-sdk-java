// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.v2;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * <p>
 * Encrypts and then decrypts data using an AWS KMS customer master key in discovery mode.
 * Discovery mode is useful when you use an alias to identify a CMK when encrypting and the
 * underlying key ARN might vary in each AWS Region.
 * <p>
 * Arguments:
 * <ol>
 * <li>Key Name: An identifier for the AWS KMS customer master key (CMK) to use. For example,
 *     a key ARN or an alias name.
 *     See https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id for
 *     a description of AWS KMS key identifiers.
 * <li>Partition: The partition that the AWS KMS customer master key belongs in. This is usually "aws".
 * <li>Account ID: The identifier for the account that the AWS KMS customer master key belongs in.
 * <li>Region Name: The region that the AWS KMS customer master key belongs in.
 * </ol>
 */
public class RestrictRegionExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        final String keyName = args[0];
        final String partition = args[1];
        final String accountId = args[2];
        final Region region = Region.of(args[3]);

        encryptAndDecrypt(keyName, partition, accountId, region);
    }

    static void encryptAndDecrypt(final String keyName, final String partition, final String accountId, final Region region) {
        // Instantiate the SDK.
        // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
        // which enforces that this client only encrypts using committing algorithm suites and enforces
        // that this client will only decrypt encrypted messages that were created with a committing algorithm suite.
        // This is the default commitment policy if you build the client with `AwsCrypto.builder().build()`
        // or `AwsCrypto.standard()`.
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();

        // 2. Instantiate the AWS KMS client for the desired region
        final KmsClient kmsClient = KmsClient.builder().region(region).build();

        // 3. Instantiate an AWS KMS master key provider for encryption.
        //
        // In strict mode (`buildStrict`), the AWS KMS master key provider will only encrypt and decrypt using the key
        // indicated by keyName.
        // This example uses an AWS KMS CMK ARN. Because this master key provider will
        // only be used for encryption, an AWS KMS CMK alias could also be used.
        final KmsMasterKeyProvider encryptingKeyProvider = KmsMasterKeyProvider.builder().buildStrict(keyName);

        // 4. Create an encryption context
        //
        // Most encrypted data should have an associated encryption context
        // to protect integrity. This sample uses placeholder values.
        //
        // For more information see:
        // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        // 5. Encrypt the data
        final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(encryptingKeyProvider, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        // 6. Instantiate a Discovery Filter to restrict which AWS KMS CMKs an AWS KMS master key provider
        // is allowed to attempt decryption with to a particular partition and account.
        // Configuring a Discovery AWS KMS master key provider with a Discovery Filter is a best practice,
        // but is not required to restrict the CMKs by region.
        final DiscoveryFilter discoveryFilter = new DiscoveryFilter(partition, accountId);

        // 7. Instantiate an AWS KMS master key provider for decryption in discovery mode (`buildDiscovery`) with a
        // custom client factory for the desired region.
        //
        // The custom client factory will only attempt to decrypt using CMKs from the desired region,
        // and skip any CMK not in the desired region.
        // If the encrypted message contains no CMKs within the desired region, decryption fails.
        //
        // In discovery mode, the AWS KMS master key provider will attempt to decrypt using AWS KMS ARNs
        // indicated in the encrypted message.
        // This example also configures the AWS KMS master key provider with a Discovery Filter to limit
        // the attempted AWS KMS CMKs to a particular partition and account.
        final KmsMasterKeyProvider decryptingKeyProvider = KmsMasterKeyProvider.builder()
                .customRegionalClientSupplier(cmkRegion -> {
                    if(cmkRegion.equals(region)) {
                        // return the previously built AWS KMS client so that we do
                        // not create a new client on every decrypt call.
                        return kmsClient;
                    }

                    throw new AwsCryptoException("Only " + region.id() + " is supported");
                })
                .buildDiscovery(discoveryFilter);

        // 8. Decrypt the data
        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(decryptingKeyProvider, ciphertext);

        // 9. Verify that the encryption context in the result contains the
        // encryption context supplied to the encryptData method. Because the
        // SDK can add values to the encryption context, don't require that
        // the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 10. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
