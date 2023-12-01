// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkDiscoveryMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * Encrypts and then decrypts data using an Aws Kms Multi-Region Discovery Keyring. Discovery mode
 * is useful when you can't or don't want to specify a CMK on decrypt.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key Name: A key identifier for the AWS KMS customer master key (CMK). For example, a key
 *       ARN or a key alias. For details, see "Key identifiers" at
 *       https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
 *   <li>Partition: The partition of the AWS KMS customer master key, which is usually "aws." A
 *       partition is a group of regions. The partition is the second element in the key ARN, e.g.
 *       "arn" in "aws:aws: ..." For details, see:
 *       https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arns-syntax
 *   <li>Account ID: The identifier for the account of the AWS KMS customer master key.
 * </ol>
 */
public class DiscoveryMultiRegionDecryptionKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyName = args[0];
    final String partition = args[1];
    final String accountId = args[2];
    final String discoveryMrkRegion = args[3];

    encryptAndDecryptWithKeyring(keyName, partition, accountId, discoveryMrkRegion);
  }

  static void encryptAndDecryptWithKeyring(
      final String keyName,
      final String partition,
      final String accountId,
      final String discoveryMrkRegion) {
    // 1. Instantiate the SDK
    // This builds the AwsCrypto client with
    // the RequireEncryptRequireDecrypt commitment policy,
    // which decrypts only with committing algorithm suites.
    // This is the default commitment policy
    // if you build the client with `AwsCrypto.builder().build()`
    // or `AwsCrypto.standard()`.
    final AwsCrypto crypto =
        AwsCrypto.builder()
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
    final AwsKmsMrkAwareMasterKeyProvider encryptingKeyProvider =
        AwsKmsMrkAwareMasterKeyProvider.builder().buildStrict(keyName);

    // 2. Create the AWS KMS keyring.
    // We create a multi keyring, as this interface creates the KMS client for us automatically.
    final MaterialProviders materialProviders =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsMultiKeyringInput encryptingInput =
        CreateAwsKmsMultiKeyringInput.builder().generator(keyName).build();
    final IKeyring encryptingKmsKeyring =
        materialProviders.CreateAwsKmsMultiKeyring(encryptingInput);

    // 3. Create an encryption context
    // Most encrypted data
    // should have an associated encryption context
    // to protect integrity.
    // This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 4. Encrypt the data
    final CryptoResult<byte[], AwsKmsMrkAwareMasterKey> encryptResult =
        crypto.encryptData(encryptingKeyProvider, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 5. Construct a discovery filter.
    //
    // A discovery filter limits the set of encrypted data keys
    // the keyring can use to decrypt data.
    //
    // We will only let the keyring use keys in the selected AWS accounts
    // and in the `aws` partition.
    //
    // This is the suggested config for most users; for more detailed config, see
    // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html#kms-keyring-discovery
    final DiscoveryFilter discoveryFilter =
        DiscoveryFilter.builder()
            .accountIds(Collections.singletonList(accountId))
            .partition(partition)
            .build();

    // 6. Construct a discovery keyring
    // with a Discovery Mrk Region
    // and with a discovery filter.
    //
    // In discovery mode, the AWS KMS multi region optimized keyring
    // attempts to decrypt only by using AWS KMS keys indicated in the encrypted message.
    // By configuring the master key provider with a Discovery Mrk Region,
    // this keyring will only attempt to decrypt
    // with AWS KMS multi-Region keys in the Discovery Mrk Region.
    // If the Discovery Mrk Region is not configured,
    // it is limited to the Region configured for the AWS SDK.
    final CreateAwsKmsMrkDiscoveryMultiKeyringInput decryptingInput =
        CreateAwsKmsMrkDiscoveryMultiKeyringInput.builder()
            .discoveryFilter(discoveryFilter)
            .regions(Collections.singletonList(discoveryMrkRegion))
            .build();
    final IKeyring decryptingKeyring =
        materialProviders.CreateAwsKmsMrkDiscoveryMultiKeyring(decryptingInput);

    // 7. Decrypt the data
    // Even though the message was encrypted with an AWS KMS key in one region
    // the keyring will attempt to decrypt with the discoveryMrkRegion.
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(
            decryptingKeyring,
            ciphertext,
            // Verify that the encryption context in the result contains the
            // encryption context supplied to the encryptData method
            encryptionContext);

    // 8. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }
}
