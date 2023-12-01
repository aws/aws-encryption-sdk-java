// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples.keyrings;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoInputStream;
import com.amazonaws.util.IOUtils;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Demonstrate an encrypt/decrypt cycle using a Required Encryption Context CMM using an Input Stream as Input.
 * A required encryption context CMM asks for required keys in the encryption context field
 * on encrypt such that they will not be stored on the message, but WILL be included in the header signature.
 * On decrypt the client MUST supply the key/value pair(s) that were not stored to successfully decrypt the message.
 */
public class StreamingWithRequiredEncryptionContextCMMExample {
  public static void main(final String[] args) throws IOException {
    final String srcFile = args[0];
    final String keyArn = args[1];

    encryptAndDecryptWithKeyring(srcFile, keyArn);
  }

  public static void encryptAndDecryptWithKeyring(final String srcFile, final String keyArn) throws IOException {
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
                    .build();

    // Create an encryption context
    // Most encrypted data should have an associated encryption context
    // to protect integrity. This sample uses placeholder values.
    // For more information see:
    // blogs.aws.amazon.com/security/post/Tx2LZ6WBJJANTNW/How-to-Protect-the-Integrity-of-Your-Encrypted-Data-by-Using-AWS-Key-Management
    final Map<String, String> encryptionContext = new HashMap<>();
    encryptionContext.put("key1", "value1");
    encryptionContext.put("key2", "value2");
    encryptionContext.put("requiredKey1", "requiredValue1");
    encryptionContext.put("requiredKey2", "requiredValue2");

    // Create list of required encryption context keys.
    // This is a list of keys that must be present in the encryption context.
    final List<String> requiredEncryptionContextKeys =
            Arrays.asList("requiredKey1", "requiredKey2");

    // Create the AWS KMS keyring.
    final MaterialProviders materialProviders =
            MaterialProviders.builder()
                    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
                    .build();
    final CreateAwsKmsKeyringInput keyringInput =
            CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(KmsClient.create()).build();
    final IKeyring kmsKeyring = materialProviders.CreateAwsKmsKeyring(keyringInput);

    // Create the required encryption context CMM.
    final ICryptographicMaterialsManager cmm =
            materialProviders.CreateDefaultCryptographicMaterialsManager(
                    CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(kmsKeyring).build());

    final ICryptographicMaterialsManager requiredCMM =
            materialProviders.CreateRequiredEncryptionContextCMM(
                    CreateRequiredEncryptionContextCMMInput.builder()
                            .requiredEncryptionContextKeys(requiredEncryptionContextKeys)
                            .underlyingCMM(cmm)
                            .build());

    // Because the file might be too large to load into memory, we stream the data, instead of
    // loading it all at once.
    FileInputStream in = new FileInputStream(srcFile);
    CryptoInputStream encryptingStream =
        crypto.createEncryptingStream(requiredCMM, in, encryptionContext);

    FileOutputStream out = new FileOutputStream(srcFile + ".encrypted");
    IOUtils.copy(encryptingStream, out);
    encryptingStream.close();
    out.close();

    // Decrypt the file.
    in = new FileInputStream(srcFile + ".encrypted");
    CryptoInputStream decryptingStream =
        crypto.createDecryptingStream(cmm, in, encryptionContext);

    // Write the plaintext data to disk.
    out = new FileOutputStream(srcFile + ".decrypted");
    IOUtils.copy(decryptingStream, out);
    decryptingStream.close();
    out.close();

    File file1 = new File(srcFile);
    File file2 = new File(srcFile + ".decrypted");
    assertTrue(org.apache.commons.io.FileUtils.contentEquals(file1, file2));
  }
}
