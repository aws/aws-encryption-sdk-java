// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * This example creates a new multi-keyring which takes in multiple keyrings and uses them to
 * encrypt and decrypt data. This example keyring consisting of an AWS KMS keyring (labeled the
 * "generator keyring") and a raw AES keyring (labeled as the only "child keyring"). Data encrypted
 * with a multi-keyring can be decrypted with any of its component keyrings.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *       key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 *
 * <p>This example takes in an `aesKeyBytes` parameter. This parameter should be a ByteBuffer
 * representing a 256-bit AES key. If this example is run through the class' main method, it will
 * create a new key.
 */
public class MultiKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyArn = args[0];

    // Generate a new AES key
    ByteBuffer aesKeyBytes = generateAesKeyBytes();

    encryptAndDecryptWithKeyring(keyArn, aesKeyBytes);
  }

  public static void encryptAndDecryptWithKeyring(String keyArn, ByteBuffer aesKeyBytes) {
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

    // 2. Create the raw AES keyring.
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateRawAesKeyringInput createRawAesKeyringInput =
        CreateRawAesKeyringInput.builder()
            .keyName("my-aes-key-name")
            .keyNamespace("my-key-namespace")
            .wrappingKey(aesKeyBytes)
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build();
    IKeyring rawAesKeyring = matProv.CreateRawAesKeyring(createRawAesKeyringInput);

    // 3. Create the AWS KMS keyring.
    //    We create a multi keyring, as this interface creates the KMS client for us automatically.
    final CreateAwsKmsMultiKeyringInput kmsMultiKeyringInput =
        CreateAwsKmsMultiKeyringInput.builder().generator(keyArn).build();
    IKeyring kmsKeyring = matProv.CreateAwsKmsMultiKeyring(kmsMultiKeyringInput);

    // 4. Create the multi-keyring.
    //    We will label the AWS KMS keyring as the generator and the raw AES keyring as the
    //        only child keyring.
    //    You must provide a generator keyring to encrypt data.
    //    You may provide additional child keyrings. Each child keyring will be able to
    //        decrypt data encrypted with the multi-keyring on its own. It does not need
    //        knowledge of any other child keyrings or the generator keyring to decrypt.
    final CreateMultiKeyringInput createMultiKeyringInput =
        CreateMultiKeyringInput.builder()
            .generator(kmsKeyring)
            .childKeyrings(Collections.singletonList(rawAesKeyring))
            .build();
    final IKeyring multiKeyring = matProv.CreateMultiKeyring(createMultiKeyringInput);

    // 5. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 6. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(multiKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 7. Decrypt the data with the Multi Keyring that originally encrypted this data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(
            multiKeyring,
            ciphertext,
            // Verify that the encryption context in the result contains the
            // encryption context supplied to the encryptData method
            encryptionContext);

    // 8. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // 9. Now show that the encrypted message can also be decrypted by child keyrings
    // configured with either CMK.
    final CryptoResult<byte[], ?> aesKeyringDecryptResult =
        crypto.decryptData(rawAesKeyring, ciphertext, encryptionContext);
    final CryptoResult<byte[], ?> kmsKeyringDecryptResult =
        crypto.decryptData(kmsKeyring, ciphertext, encryptionContext);

    // 10. Verify that the decrypted plaintext matches the original plaintext for each decryption
    assert Arrays.equals(aesKeyringDecryptResult.getResult(), EXAMPLE_DATA);
    assert Arrays.equals(kmsKeyringDecryptResult.getResult(), EXAMPLE_DATA);
  }

  public static ByteBuffer generateAesKeyBytes() {
    // This example uses BouncyCastle's KeyGenerator to generate the key bytes.
    // In practice, you should not generate this key in your code, and should instead
    //     retrieve this key from a secure key management system (e.g. HSM).
    // This key is created here for example purposes only and should not be used for any other
    // purpose.
    KeyGenerator aesGen;
    try {
      aesGen = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("No such algorithm", e);
    }
    aesGen.init(256, new SecureRandom());
    SecretKey encryptionKey = aesGen.generateKey();
    ByteBuffer encryptionKeyByteBuffer = ByteBuffer.wrap(encryptionKey.getEncoded());
    return encryptionKeyByteBuffer;
  }
}
