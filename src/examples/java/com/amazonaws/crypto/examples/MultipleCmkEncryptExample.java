// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * Encrypts data using two different AWS KMS customer master keys, which can then be decrypted by
 * configuring an AWS KMS master key provider in strict mode (`buildStrict`) with at least one of
 * either key.
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
public class MultipleCmkEncryptExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyArn1 = args[0];
    final String keyArn2 = args[1];

    encryptAndDecrypt(keyArn1, keyArn2);
  }

  static void encryptAndDecrypt(final String keyArn1, final String keyArn2) {
    // 1. Instantiate the SDK with a specific commitment policy.
    // ForbidEncryptAllowDecrypt is the only available policy in 1.7.0.
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();

    // 2. Instantiate an AWS KMS master key provider to encrypt with
    // In strict mode (`buildStrict`), the AWS KMS master key provider encrypts and decrypts only by
    // using the
    // keys indicated by keyArn1 and keyArn2
    final KmsMasterKeyProvider multiCmkKeyProvider =
        KmsMasterKeyProvider.builder().buildStrict(keyArn1, keyArn2);

    // 3. Instantiate an AWS KMS master key providers that are configured with keyArn1 and keyArn2
    // separately.
    // These will be used later in this example to show that the encrypted messages created by
    // multiCmkKeyProvider
    // can be decrypted by AWS KMS master key providers that are configured with either CMK.
    final KmsMasterKeyProvider singleCMKKeyProvider1 =
        KmsMasterKeyProvider.builder().buildStrict(keyArn1);
    final KmsMasterKeyProvider singleCMKKeyProvider2 =
        KmsMasterKeyProvider.builder().buildStrict(keyArn2);

    // 4. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 5. Encrypt the data
    final CryptoResult<byte[], KmsMasterKey> encryptResult =
        crypto.encryptData(multiCmkKeyProvider, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 6. Decrypt the data with the AWS KMS master key provider that originally encrypted this data
    final CryptoResult<byte[], KmsMasterKey> decryptResult =
        crypto.decryptData(multiCmkKeyProvider, ciphertext);

    // 7. Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method. Because the
    // SDK can add values to the encryption context, don't require that
    // the entire context matches.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // 8. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // 9. Now show that the encrypted message can also be decrypted by AWS KMS master key providers
    // configured with either CMK.
    final CryptoResult<byte[], KmsMasterKey> singleCmkDecryptResult1 =
        crypto.decryptData(singleCMKKeyProvider1, ciphertext);
    final CryptoResult<byte[], KmsMasterKey> singleCmkDecryptResult2 =
        crypto.decryptData(singleCMKKeyProvider2, ciphertext);

    // 10. Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method for both decryptions
    if (!encryptionContext.entrySet().stream()
        .allMatch(
            e ->
                e.getValue()
                    .equals(singleCmkDecryptResult1.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }
    if (!encryptionContext.entrySet().stream()
        .allMatch(
            e ->
                e.getValue()
                    .equals(singleCmkDecryptResult2.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // 11. Verify that the decrypted plaintext matches the original plaintext for each decryption
    assert Arrays.equals(singleCmkDecryptResult1.getResult(), EXAMPLE_DATA);
    assert Arrays.equals(singleCmkDecryptResult2.getResult(), EXAMPLE_DATA);
  }
}
