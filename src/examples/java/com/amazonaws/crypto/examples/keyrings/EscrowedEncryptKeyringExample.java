// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoOutputStream;
import com.amazonaws.util.IOUtils;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.PaddingScheme;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

/**
 * Encrypts a file using both AWS KMS Key and an asymmetric key pair.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *       key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 *   <li>Name of file containing plaintext data to encrypt
 * </ol>
 *
 * <p>You might use AWS Key Management Service (AWS KMS) for most encryption and decryption
 * operations, but still want the option of decrypting your data offline independently of AWS KMS.
 * This sample demonstrates one way to do this.
 *
 * <p>The sample encrypts data under both an AWS KMS customer master key (CMK) and an "escrowed" RSA
 * key pair so that either key alone can decrypt it. You might commonly use the AWS KMS CMK for
 * decryption. However, at any time, you can use the private RSA key to decrypt the ciphertext
 * independent of AWS KMS.
 *
 * <p>This sample uses the RawRsaKeyring to generate a RSA public-private key pair and saves the key
 * pair in memory. In practice, you would store the private key in a secure offline location, such
 * as an offline HSM, and distribute the public key to your development team.
 */
public class EscrowedEncryptKeyringExample {
  private static ByteBuffer publicEscrowKey;
  private static ByteBuffer privateEscrowKey;

  public static void main(final String[] args) throws Exception {
    // This sample generates a new random key for each operation.
    // In practice, you would distribute the public key and save the private key in secure
    // storage.
    generateEscrowKeyPair();

    final String kmsArn = args[0];
    final String fileName = args[1];

    standardEncrypt(kmsArn, fileName);
    standardDecrypt(kmsArn, fileName);

    escrowDecrypt(fileName);
  }

  private static void standardEncrypt(final String kmsArn, final String fileName) throws Exception {
    // Encrypt with the KMS CMK and the escrowed public key
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
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsMultiKeyringInput keyringInput =
        CreateAwsKmsMultiKeyringInput.builder().generator(kmsArn).build();
    final IKeyring kmsKeyring = matProv.CreateAwsKmsMultiKeyring(keyringInput);

    // 3. Create the Raw Rsa Keyring with Public Key.
    final CreateRawRsaKeyringInput encryptingKeyringInput =
        CreateRawRsaKeyringInput.builder()
            .keyName("Escrow")
            .keyNamespace("Escrow")
            .paddingScheme(PaddingScheme.OAEP_SHA512_MGF1)
            .publicKey(publicEscrowKey)
            .build();
    IKeyring rsaPublicKeyring = matProv.CreateRawRsaKeyring(encryptingKeyringInput);

    // 4. Create the multi-keyring.
    final CreateMultiKeyringInput createMultiKeyringInput =
        CreateMultiKeyringInput.builder()
            .generator(kmsKeyring)
            .childKeyrings(Collections.singletonList(rsaPublicKeyring))
            .build();
    IKeyring multiKeyring = matProv.CreateMultiKeyring(createMultiKeyringInput);

    // 5. Encrypt the file
    // To simplify the code, we omit the encryption context. Production code should always
    // use an encryption context. For an example, see the other SDK samples.
    final FileInputStream in = new FileInputStream(fileName);
    final FileOutputStream out = new FileOutputStream(fileName + ".encrypted");
    final CryptoOutputStream<?> encryptingStream = crypto.createEncryptingStream(multiKeyring, out);

    IOUtils.copy(in, encryptingStream);
    in.close();
    encryptingStream.close();
  }

  private static void standardDecrypt(final String kmsArn, final String fileName) throws Exception {
    // Decrypt with the AWS KMS CMK and the escrow public key. You can use a combined provider,
    // as shown here, or just the AWS KMS master key provider.

    // 1. Instantiate the SDK.
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
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsMultiKeyringInput keyringInput =
        CreateAwsKmsMultiKeyringInput.builder().generator(kmsArn).build();
    IKeyring kmsKeyring = matProv.CreateAwsKmsMultiKeyring(keyringInput);

    // 3. Create the Raw Rsa Keyring with Public Key.
    final CreateRawRsaKeyringInput encryptingKeyringInput =
        CreateRawRsaKeyringInput.builder()
            .keyName("Escrow")
            .keyNamespace("Escrow")
            .paddingScheme(PaddingScheme.OAEP_SHA512_MGF1)
            .publicKey(publicEscrowKey)
            .build();
    IKeyring rsaPublicKeyring = matProv.CreateRawRsaKeyring(encryptingKeyringInput);

    // 4. Create the multi-keyring.
    final CreateMultiKeyringInput createMultiKeyringInput =
        CreateMultiKeyringInput.builder()
            .generator(kmsKeyring)
            .childKeyrings(Collections.singletonList(rsaPublicKeyring))
            .build();
    IKeyring multiKeyring = matProv.CreateMultiKeyring(createMultiKeyringInput);

    // 5. Decrypt the file
    // To simplify the code, we omit the encryption context. Production code should always
    // use an encryption context. For an example, see the other SDK samples.
    final FileInputStream in = new FileInputStream(fileName + ".encrypted");
    final FileOutputStream out = new FileOutputStream(fileName + ".decrypted");
    // Since we are using a signing algorithm suite, we avoid streaming decryption directly to the
    // output file,
    // to ensure that the trailing signature is verified before writing any untrusted plaintext to
    // disk.
    final ByteArrayOutputStream plaintextBuffer = new ByteArrayOutputStream();
    final CryptoOutputStream<?> decryptingStream =
        crypto.createDecryptingStream(multiKeyring, plaintextBuffer);
    IOUtils.copy(in, decryptingStream);
    in.close();
    decryptingStream.close();
    final ByteArrayInputStream plaintextReader =
        new ByteArrayInputStream(plaintextBuffer.toByteArray());
    IOUtils.copy(plaintextReader, out);
    out.close();
  }

  private static void escrowDecrypt(final String fileName) throws Exception {
    // You can decrypt the stream using only the private key.
    // This method does not call AWS KMS.

    // 1. Instantiate the SDK
    final AwsCrypto crypto = AwsCrypto.standard();

    // 2. Create the Raw Rsa Keyring with Private Key.
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateRawRsaKeyringInput encryptingKeyringInput =
        CreateRawRsaKeyringInput.builder()
            .keyName("Escrow")
            .keyNamespace("Escrow")
            .paddingScheme(PaddingScheme.OAEP_SHA512_MGF1)
            .publicKey(publicEscrowKey)
            .privateKey(privateEscrowKey)
            .build();
    IKeyring escrowPrivateKeyring = matProv.CreateRawRsaKeyring(encryptingKeyringInput);

    // 3. Decrypt the file
    // To simplify the code, we omit the encryption context. Production code should always
    // use an encryption context. For an example, see the other SDK samples.
    final FileInputStream in = new FileInputStream(fileName + ".encrypted");
    final FileOutputStream out = new FileOutputStream(fileName + ".deescrowed");
    final CryptoOutputStream<?> decryptingStream =
        crypto.createDecryptingStream(escrowPrivateKeyring, out);
    IOUtils.copy(in, decryptingStream);
    in.close();
    decryptingStream.close();
  }

  private static void generateEscrowKeyPair() throws GeneralSecurityException {
    final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
    kg.initialize(4096); // Escrow keys should be very strong
    final KeyPair keyPair = kg.generateKeyPair();
    publicEscrowKey = RawRsaKeyringExample.getPEMPublicKey(keyPair.getPublic());
    privateEscrowKey = RawRsaKeyringExample.getPEMPrivateKey(keyPair.getPrivate());
  }
}
