// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.PaddingScheme;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Encrypts and then decrypts data using an Raw Rsa Keyring. This example takes in Rsa Key Pair. If
 * this example is run through the class' main method, it will create a new key pair. In practice,
 * users of this library should not generate new key pairs like this, and should instead retrieve an
 * existing key from a secure key management system (e.g. an HSM).
 */
public class RawRsaKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    KeyPair keyPair = generateKeyPair();
    ByteBuffer publicKeyBytes = getPEMPublicKey(keyPair.getPublic());
    ByteBuffer privateKeyBytes = getPEMPrivateKey(keyPair.getPrivate());

    encryptAndDecryptWithKeyring(publicKeyBytes, privateKeyBytes);
  }

  public static void encryptAndDecryptWithKeyring(
      final ByteBuffer publicKeyBytes, final ByteBuffer privateKeyBytes) {
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

    // 2. Create the Raw Rsa Keyring with Public Key for Encryption.
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateRawRsaKeyringInput encryptingKeyringInput =
        CreateRawRsaKeyringInput.builder()
            .keyName("rsa-key")
            .keyNamespace("rsa-keyring")
            .paddingScheme(PaddingScheme.PKCS1)
            .publicKey(publicKeyBytes)
            .build();
    final IKeyring encryptingKeyring = matProv.CreateRawRsaKeyring(encryptingKeyringInput);

    // 3. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 4. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(encryptingKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 5. Create the Raw Rsa Keyring with Private Key for Decryption.
    final CreateRawRsaKeyringInput decryptingKeyringInput =
        CreateRawRsaKeyringInput.builder()
            .keyName("rsa-key")
            .keyNamespace("rsa-keyring")
            .paddingScheme(PaddingScheme.PKCS1)
            .privateKey(privateKeyBytes)
            .build();
    final IKeyring decryptingKeyring = matProv.CreateRawRsaKeyring(decryptingKeyringInput);

    // 6. Decrypt the data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(
            decryptingKeyring,
            ciphertext,
            // Verify that the encryption context in the result contains the
            // encryption context supplied to the encryptData method
            encryptionContext);

    // 7. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  public static KeyPair generateKeyPair() {
    KeyPairGenerator rsaGen;
    try {
      rsaGen = KeyPairGenerator.getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("No such algorithm", e);
    }
    rsaGen.initialize(2048, new SecureRandom());
    return rsaGen.generateKeyPair();
  }

  public static ByteBuffer getPEMPublicKey(PublicKey publicKey) {
    StringWriter publicKeyStringWriter = new StringWriter();
    PemWriter publicKeyPemWriter = new PemWriter(publicKeyStringWriter);
    try {
      publicKeyPemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
      publicKeyPemWriter.close();
    } catch (IOException e) {
      throw new RuntimeException("IOException while writing public key PEM", e);
    }
    return StandardCharsets.UTF_8.encode(publicKeyStringWriter.toString());
  }

  public static ByteBuffer getPEMPrivateKey(PrivateKey privateKey) {
    StringWriter privateKeyStringWriter = new StringWriter();
    PemWriter privateKeyPemWriter = new PemWriter(privateKeyStringWriter);
    try {
      privateKeyPemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
      privateKeyPemWriter.close();
    } catch (IOException e) {
      throw new RuntimeException("IOException while writing private key PEM", e);
    }
    return StandardCharsets.UTF_8.encode(privateKeyStringWriter.toString());
  }
}
