// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.*;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.util.IOUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;

/**
 * Encrypts and then decrypts a file under a random key.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Name of file containing plaintext data to encrypt
 * </ol>
 *
 * <p>This program demonstrates using a standard Java {@link SecretKey} object as a {@link
 * MasterKey} to encrypt and decrypt streaming data.
 */
public class FileStreamingExample {
  private static String srcFile;

  public static void main(String[] args) throws IOException {
    srcFile = args[0];

    // In this example, we generate a random key. In practice,
    // you would get a key from an existing store
    SecretKey cryptoKey = retrieveEncryptionKey();

    // Create a JCE master key provider using the random key and an AES-GCM encryption algorithm
    JceMasterKey masterKey =
        JceMasterKey.getInstance(cryptoKey, "Example", "RandomKey", "AES/GCM/NoPadding");

    // Instantiate the SDK with a specific commitment policy.
    // ForbidEncryptAllowDecrypt is the only available policy in 1.7.0.
    // This also chooses to encrypt with an algorithm suite that doesn't include signing for faster
    // decryption,
    // since this use case assumes that the contexts that encrypt and decrypt are equally trusted.
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
            .build();

    // Create an encryption context to identify this ciphertext
    Map<String, String> context = Collections.singletonMap("Example", "FileStreaming");

    // Because the file might be to large to load into memory, we stream the data, instead of
    // loading it all at once.
    FileInputStream in = new FileInputStream(srcFile);
    CryptoInputStream<JceMasterKey> encryptingStream =
        crypto.createEncryptingStream(masterKey, in, context);

    FileOutputStream out = new FileOutputStream(srcFile + ".encrypted");
    IOUtils.copy(encryptingStream, out);
    encryptingStream.close();
    out.close();

    // Decrypt the file. Verify the encryption context before returning the plaintext.
    // Since we encrypted using an unsigned algorithm suite, we can use the recommended
    // createUnsignedMessageDecryptingStream method that only accepts unsigned messages.
    in = new FileInputStream(srcFile + ".encrypted");
    CryptoInputStream<JceMasterKey> decryptingStream =
        crypto.createUnsignedMessageDecryptingStream(masterKey, in);
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
