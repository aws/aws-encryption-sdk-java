// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
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
 * Configures a client with a specific encryption algorithm, then encrypts and decrypts data using
 * that encryption algorithm and an Aws Kms Keyring.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *       key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class SetEncryptionAlgorithmKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyArn = args[0];

    encryptAndDecryptWithKeyring(keyArn);
  }

  public static void encryptAndDecryptWithKeyring(final String keyArn) {
    // 1. Instantiate the SDK with the algorithm for encryption
    //
    // `withEncryptionAlgorithm(cryptoAlgorithm)` configures the client to encrypt
    // using a specified encryption algorithm.
    // This example sets the encryption algorithm to
    // `CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY`,
    // which is an algorithm that does not contain message signing.
    //
    // If this value is not set, the client encrypts with the recommended default:
    // `CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384`.
    // We recommend using the default whenever possible.
    // For a description of our supported algorithms, see
    // https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html
    //
    // You can update the encryption algorithm after constructing the client
    // by using `crypto.setEncryptionAlgorithm(CryptoAlgorithm)`.
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .build();

    // 2. Create the AWS KMS keyring.
    // We create a multi keyring, as this interface creates the KMS client for us automatically.
    final MaterialProviders materialProviders =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsMultiKeyringInput encryptingInput =
        CreateAwsKmsMultiKeyringInput.builder().generator(keyArn).build();
    final IKeyring kmsKeyring = materialProviders.CreateAwsKmsMultiKeyring(encryptingInput);

    // 3. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 4. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(kmsKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 5. Decrypt the data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(
            kmsKeyring,
            ciphertext,
            // Verify that the encryption context in the result contains the
            // encryption context supplied to the encryptData method
            encryptionContext);

    // 6. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }
}
