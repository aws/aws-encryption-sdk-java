// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsDiscoveryMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * Encrypts and then decrypts data using an Aws Kms Discovery Keyring. Discovery mode is useful when
 * you use an alias to identify a CMK when encrypting and the underlying key ARN might vary in each
 * AWS Region.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key Name: An identifier for the AWS KMS customer master key (CMK) to use. For example, a
 *       key ARN or a key alias. For help finding the Amazon Resource Name (ARN) of your AWS KMS
 *       customer master key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 *   <li>Partition: The partition of the AWS KMS customer master key, which is usually "aws." A
 *       partition is a group of regions. The partition is the second element in the key ARN, e.g.
 *       "arn" in "aws:aws: ..."
 *   <li>Account ID: The identifier for the account of the AWS KMS customer master key.
 * </ol>
 */
public class DiscoveryDecryptionKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyName = args[0];
    final String partition = args[1];
    final String accountId = args[2];
    final String region = args[3];

    encryptAndDecryptWithKeyring(keyName, partition, accountId, region);
  }

  public static void encryptAndDecryptWithKeyring(
      final String keyName, final String partition, final String accountId, final String region) {
    // 1. Instantiate the SDK
    // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
    // which enforces that this client only encrypts using committing algorithm suites and enforces
    // that this client will only decrypt encrypted messages that were created with a committing
    // algorithm suite.
    // This is the default commitment policy if you build the client with
    // `AwsCrypto.builder().build()`
    // or `AwsCrypto.standard()`.
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

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
    //
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    //
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 4. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(encryptingKmsKeyring, EXAMPLE_DATA, encryptionContext);
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

    // 6. Construct a discovery keyring.
    final CreateAwsKmsDiscoveryMultiKeyringInput decryptingInput =
        CreateAwsKmsDiscoveryMultiKeyringInput.builder()
            .discoveryFilter(discoveryFilter)
            .regions(Collections.singletonList(region))
            .build();
    final IKeyring decryptingKeyring =
        materialProviders.CreateAwsKmsDiscoveryMultiKeyring(decryptingInput);

    // 7. Decrypt the data
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
