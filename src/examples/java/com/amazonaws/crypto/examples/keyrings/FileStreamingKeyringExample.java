// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoInputStream;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.util.IOUtils;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and then decrypts a file under a random key.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Name of file containing plaintext data to encrypt
 * </ol>
 *
 * <p>This program demonstrates using a standard Java {@link SecretKey} object as a {@link IKeyring}
 * to encrypt and decrypt streaming data.
 */
public class FileStreamingKeyringExample {
  private static String srcFile;

  public static void main(String[] args) throws IOException {
    srcFile = args[0];

    // In this example, we generate a random key. In practice,
    // you would get a key from an existing store
    SecretKey cryptoKey = retrieveEncryptionKey();

    // Create a Raw Aes Keyring using the random key and an AES-GCM encryption algorithm
    final MaterialProviders materialProviders =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateRawAesKeyringInput keyringInput =
        CreateRawAesKeyringInput.builder()
            .wrappingKey(ByteBuffer.wrap(cryptoKey.getEncoded()))
            .keyNamespace("Example")
            .keyName("RandomKey")
            .wrappingAlg(AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16)
            .build();
    final IKeyring keyring = materialProviders.CreateRawAesKeyring(keyringInput);

    // Instantiate the SDK.
    // This builds the AwsCrypto client with the RequireEncryptRequireDecrypt commitment policy,
    // which enforces that this client only encrypts using committing algorithm suites and enforces
    // that this client will only decrypt encrypted messages that were created with a committing
    // algorithm suite.
    // This is the default commitment policy if you build the client with
    // `AwsCrypto.builder().build()`
    // or `AwsCrypto.standard()`.
    // This also chooses to encrypt with an algorithm suite that doesn't include signing for faster
    // decryption,
    // since this use case assumes that the contexts that encrypt and decrypt are equally trusted.
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .build();

    // Create an encryption context to identify this ciphertext
    Map<String, String> context = Collections.singletonMap("Example", "FileStreaming");

    // Because the file might be to large to load into memory, we stream the data, instead of
    // loading it all at once.
    FileInputStream in = new FileInputStream(srcFile);
    CryptoInputStream<JceMasterKey> encryptingStream =
        crypto.createEncryptingStream(keyring, in, context);

    FileOutputStream out = new FileOutputStream(srcFile + ".encrypted");
    IOUtils.copy(encryptingStream, out);
    encryptingStream.close();
    out.close();

    // Decrypt the file. Verify the encryption context before returning the plaintext.
    // Since we encrypted using an unsigned algorithm suite, we can use the recommended
    // createUnsignedMessageDecryptingStream method that only accepts unsigned messages.
    in = new FileInputStream(srcFile + ".encrypted");
    CryptoInputStream<JceMasterKey> decryptingStream =
        crypto.createUnsignedMessageDecryptingStream(keyring, in);
    // Does it contain the expected encryption context?
    if (!"FileStreaming"
        .equals(decryptingStream.getCryptoResult().getEncryptionContext().get("Example"))) {
      throw new IllegalStateException("Bad encryption context");
    }

    // Write the plaintext data to disk.
    out = new FileOutputStream(srcFile + ".decrypted");
    IOUtils.copy(decryptingStream, out);
    decryptingStream.close();
    out.close();
  }

  /**
   * In practice, this key would be saved in a secure location. For this demo, we generate a new
   * random key for each operation.
   */
  private static SecretKey retrieveEncryptionKey() {
    SecureRandom rnd = new SecureRandom();
    byte[] rawKey = new byte[16]; // 128 bits
    rnd.nextBytes(rawKey);
    return new SecretKeySpec(rawKey, "AES");
  }
}
