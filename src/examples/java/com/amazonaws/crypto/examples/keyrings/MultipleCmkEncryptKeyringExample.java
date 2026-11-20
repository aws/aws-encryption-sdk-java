// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * This example creates a new multi-keyring which takes in multiple keyrings and uses them to
 * encrypt and decrypt data. This example keyring consisting of an AWS KMS keyring (labeled the
 * "generator keyring") and another AWS KMS keyring (labeled as the only "child keyring"). Data
 * encrypted with a multi-keyring can be decrypted with any of its component keyrings.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key ARN 1: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *       key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 *   <li>Key ARN 2: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *       key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class MultipleCmkEncryptKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyArn1 = args[0];
    final String keyArn2 = args[1];

    encryptAndDecryptWithKeyring(keyArn1, keyArn2);
  }

  public static void encryptAndDecryptWithKeyring(final String keyArn1, final String keyArn2) {
    // Instantiate the SDK.
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

    // 2. Create the multi-keyring.
    //    We will label the AWS KMS keyring as the generator and the raw AES keyring as the
    //        only child keyring.
    //    You must provide a generator keyring to encrypt data.
    //    You may provide additional child keyrings. Each child keyring will be able to
    //        decrypt data encrypted with the multi-keyring on its own. It does not need
    //        knowledge of any other child keyrings or the generator keyring to decrypt.
    final MaterialProviders materialProviders =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsMultiKeyringInput encryptingInput =
        CreateAwsKmsMultiKeyringInput.builder()
            .generator(keyArn1)
            .kmsKeyIds(Arrays.asList(keyArn1, keyArn2))
            .build();
    final IKeyring multiCmkKeyring = materialProviders.CreateAwsKmsMultiKeyring(encryptingInput);

    // 3. Create the child keyrings
    //    Instantiate an AWS KMS Keyring that are configured with keyArn1 and keyArn2
    //          separately.
    //    These will be used later in this example to show that the encrypted messages created by
    // multiCmkKeyring
    //    can be decrypted by AWS KMS Keyrings that are configured with either CMK.
    final IKeyring singleCMKKeyring1 =
        materialProviders.CreateAwsKmsMultiKeyring(
            CreateAwsKmsMultiKeyringInput.builder().generator(keyArn1).build());
    final IKeyring singleCMKKeyring2 =
        materialProviders.CreateAwsKmsMultiKeyring(
            CreateAwsKmsMultiKeyringInput.builder().generator(keyArn1).build());

    // 4. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 5. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(multiCmkKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 6. Decrypt the data with the multi-keyring that originally encrypted this data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(
            multiCmkKeyring,
            ciphertext,
            // Verify that the encryption context in the result contains the
            // encryption context supplied to the encryptData method
            encryptionContext);

    // 8. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // 9. Now show that the encrypted message can also be decrypted by child keyrings
    // configured with either CMK.
    final CryptoResult<byte[], ?> singleCmkDecryptResult1 =
        crypto.decryptData(singleCMKKeyring1, ciphertext, encryptionContext);
    final CryptoResult<byte[], ?> singleCmkDecryptResult2 =
        crypto.decryptData(singleCMKKeyring2, ciphertext, encryptionContext);

    // 10. Verify that the decrypted plaintext matches the original plaintext for each decryption
    assert Arrays.equals(singleCmkDecryptResult1.getResult(), EXAMPLE_DATA);
    assert Arrays.equals(singleCmkDecryptResult2.getResult(), EXAMPLE_DATA);
  }
}
