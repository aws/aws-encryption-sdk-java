// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Encrypts and then decrypts data using an AWS KMS RSA Keyring. This keyring uses a KMS RSA key
 * pair to encrypt and decrypt data. The client uses the downloaded public key to encrypt data and
 * uses the private key to decrypt content, by calling KMS' decrypt API.
 *
 * <p>Arguments:
 *
 * <ol>
 *   <li>Key ARN: For help finding the Amazon Resource Name (ARN) of your AWS KMS customer master
 *       key (CMK), see 'Viewing Keys' at
 *       http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * </ol>
 */
public class AwsKmsRsaKeyringExample {
  static String DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME = "KmsRsaKeyringExamplePublicKey.pem";

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String rsaKeyArn = KMSTestFixtures.US_WEST_2_KMS_RSA_KEY_ID;
    String rsaPublicKeyFilename;
    if (args.length == 2) {
      rsaPublicKeyFilename = args[1];
    } else {
      rsaPublicKeyFilename = DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME;
    }

    // You may provide your own RSA public key at EXAMPLE_RSA_PUBLIC_KEY_FILENAME.
    // This must be the public key for the RSA key represented at rsaKeyArn.
    // If this file is not present, this will write a UTF-8 encoded PEM file for you.
    if (shouldGetNewPublicKey(rsaPublicKeyFilename)) {
      writePublicKeyPemForRsaKey(rsaKeyArn, rsaPublicKeyFilename);
    }

    encryptAndDecryptWithKeyring(rsaKeyArn, rsaPublicKeyFilename);
  }

  public static void encryptAndDecryptWithKeyring(final String rsaKeyArn) {
    String rsaPublicKeyFilename = DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME;

    if (shouldGetNewPublicKey(rsaPublicKeyFilename)) {
      writePublicKeyPemForRsaKey(rsaKeyArn, rsaPublicKeyFilename);
    }

    encryptAndDecryptWithKeyring(rsaKeyArn, rsaPublicKeyFilename);
  }

  public static void encryptAndDecryptWithKeyring(
      final String rsaKeyArn, String rsaPublicKeyFilename) {
    // 0. Load UTF-8 encoded public key PEM file.
    //    You may have an RSA public key file already defined.
    //    If not, the main method in this class will call
    //    the KMS RSA key, retrieve its public key, and store it
    //    in a PEM file for example use.
    ByteBuffer publicKeyUtf8EncodedByteBuffer;
    try {
      publicKeyUtf8EncodedByteBuffer =
          ByteBuffer.wrap(Files.readAllBytes(Paths.get(rsaPublicKeyFilename)));
    } catch (IOException e) {
      throw new RuntimeException("IOException while reading public key from file", e);
    }

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
            // Specify algorithmSuite without asymmetric signing here
            //
            // ALG_AES_128_GCM_IV12_TAG16_NO_KDF("0x0014"),
            // ALG_AES_192_GCM_IV12_TAG16_NO_KDF("0x0046"),
            // ALG_AES_256_GCM_IV12_TAG16_NO_KDF("0x0078"),
            // ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256("0x0114"),
            // ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256("0x0146"),
            // ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256("0x0178")
            .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256)
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();

    // 2. Create a KMS RSA keyring.
    //    This keyring takes in:
    //     - kmsClient
    //     - kmsKeyId: Must be an ARN representing a KMS RSA key
    //     - publicKey: A ByteBuffer of a UTF-8 encoded PEM file representing the public
    //                  key for the key passed into kmsKeyId
    //     - encryptionAlgorithm: Must be either RSAES_OAEP_SHA_256 or RSAES_OAEP_SHA_1
    final MaterialProviders matProv =
        MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    final CreateAwsKmsRsaKeyringInput createAwsKmsRsaKeyringInput =
        CreateAwsKmsRsaKeyringInput.builder()
            .kmsClient(KmsClient.create())
            .kmsKeyId(rsaKeyArn)
            .publicKey(publicKeyUtf8EncodedByteBuffer)
            .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
            .build();
    IKeyring awsKmsRsaKeyring = matProv.CreateAwsKmsRsaKeyring(createAwsKmsRsaKeyringInput);

    // 3. Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 4. Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(awsKmsRsaKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // 5. Decrypt the data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(
            awsKmsRsaKeyring,
            ciphertext,
            // Verify that the encryption context in the result contains the
            // encryption context supplied to the encryptData method
            encryptionContext);

    // 6. Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  static boolean shouldGetNewPublicKey() {
    return shouldGetNewPublicKey(DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME);
  }

  static boolean shouldGetNewPublicKey(String rsaPublicKeyFilename) {
    // Check if a public key file already exists
    File publicKeyFile = new File(rsaPublicKeyFilename);

    // If a public key file already exists: do not overwrite existing file
    if (publicKeyFile.exists()) {
      return false;
    }

    // If file is not present, generate a new key pair
    return true;
  }

  static void writePublicKeyPemForRsaKey(String rsaKeyArn) {
    writePublicKeyPemForRsaKey(rsaKeyArn, DEFAULT_EXAMPLE_RSA_PUBLIC_KEY_FILENAME);
  }

  static void writePublicKeyPemForRsaKey(String rsaKeyArn, String rsaPublicKeyFilename) {
    // Safety check: Validate file is not present
    File publicKeyFile = new File(rsaPublicKeyFilename);
    if (publicKeyFile.exists()) {
      throw new IllegalStateException("getRsaPublicKey will not overwrite existing PEM files");
    }

    // This code will call KMS to get the public key for the KMS RSA key.
    // You must have kms:GetPublicKey permissions on the key for this to succeed.
    // The public key will be written to the file EXAMPLE_RSA_PUBLIC_KEY_FILENAME.
    KmsClient getterForPublicKey = KmsClient.create();
    GetPublicKeyResponse response =
        getterForPublicKey.getPublicKey(GetPublicKeyRequest.builder().keyId(rsaKeyArn).build());
    byte[] publicKeyByteArray = response.publicKey().asByteArray();

    StringWriter publicKeyStringWriter = new StringWriter();
    PemWriter publicKeyPemWriter = new PemWriter(publicKeyStringWriter);
    try {
      publicKeyPemWriter.writeObject(new PemObject("PUBLIC KEY", publicKeyByteArray));
      publicKeyPemWriter.close();
    } catch (IOException e) {
      throw new RuntimeException("IOException while writing public key PEM", e);
    }
    ByteBuffer publicKeyUtf8EncodedByteBufferToWrite =
        StandardCharsets.UTF_8.encode(publicKeyStringWriter.toString());

    try {
      FileChannel fc = new FileOutputStream(rsaPublicKeyFilename).getChannel();
      fc.write(publicKeyUtf8EncodedByteBufferToWrite);
      fc.close();
    } catch (FileNotFoundException e) {
      throw new RuntimeException("FileNotFoundException while opening public key FileChannel", e);
    } catch (IOException e) {
      throw new RuntimeException("IOException while writing public key or closing FileChannel", e);
    }
  }
}
