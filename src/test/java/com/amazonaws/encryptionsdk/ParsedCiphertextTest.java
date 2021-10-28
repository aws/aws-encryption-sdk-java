// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static org.junit.Assert.*;
import static org.mockito.Mockito.spy;

import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;

public class ParsedCiphertextTest extends CiphertextHeaders {
  private static final int MESSAGE_FORMAT_MAX_EDKS = (1 << 16) - 1;
  private StaticMasterKey masterKeyProvider;
  private AwsCrypto encryptionClient_;

  @Before
  public void init() {
    masterKeyProvider = spy(new StaticMasterKey("testmaterial"));

    encryptionClient_ =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    encryptionClient_.setEncryptionAlgorithm(
        CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256);
  }

  @Test()
  public void goodParsedCiphertext() {
    final int byteSize = 0;
    final int frameSize = 0;
    final byte[] plaintextBytes = new byte[byteSize];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "ParsedCiphertext test with %d" + byteSize);

    encryptionClient_.setEncryptionFrameSize(frameSize);

    final byte[] cipherText =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    final ParsedCiphertext pCt = new ParsedCiphertext(cipherText);

    assertNotNull(pCt.getCiphertext());
    assertTrue(pCt.getOffset() > 0);
  }

  @Test(expected = BadCiphertextException.class)
  public void incompleteZeroByteCiphertext() {
    final byte[] cipherText = {};
    ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
  }

  @Test(expected = BadCiphertextException.class)
  public void incompleteSingleByteCiphertext() {
    final byte[] cipherText = {1 /* Original ciphertext version number */};
    ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
  }

  @Test(expected = BadCiphertextException.class)
  public void incompleteCiphertext() {
    final int byteSize = 0;
    final int frameSize = 0;
    final byte[] plaintextBytes = new byte[byteSize];

    final Map<String, String> encryptionContext = new HashMap<String, String>(1);
    encryptionContext.put("ENC1", "ParsedCiphertext test with %d" + byteSize);

    encryptionClient_.setEncryptionFrameSize(frameSize);

    final byte[] cipherText =
        encryptionClient_
            .encryptData(masterKeyProvider, plaintextBytes, encryptionContext)
            .getResult();
    ParsedCiphertext pCt = new ParsedCiphertext(cipherText);

    byte[] incompleteCiphertext = Arrays.copyOf(pCt.getCiphertext(), pCt.getOffset() - 1);
    ParsedCiphertext badPCt = new ParsedCiphertext(incompleteCiphertext);
  }

  private MasterKeyProvider<?> providerWithEdks(int numEdks) {
    List<MasterKeyProvider<?>> providers = new ArrayList<>();
    for (int i = 0; i < numEdks; i++) {
      providers.add(masterKeyProvider);
    }
    return MultipleProviderFactory.buildMultiProvider(providers);
  }

  @Test
  public void lessThanMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(2);
    CryptoResult<byte[], ?> result = encryptionClient_.encryptData(provider, new byte[] {1});
    ParsedCiphertext ciphertext = new ParsedCiphertext(result.getResult(), 3);
    assertEquals(ciphertext.getEncryptedKeyBlobCount(), 2);
  }

  @Test
  public void equalToMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(3);
    CryptoResult<byte[], ?> result = encryptionClient_.encryptData(provider, new byte[] {1});
    ParsedCiphertext ciphertext = new ParsedCiphertext(result.getResult(), 3);
    assertEquals(ciphertext.getEncryptedKeyBlobCount(), 3);
  }

  @Test
  public void failMoreThanMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(4);
    CryptoResult<byte[], ?> result = encryptionClient_.encryptData(provider, new byte[] {1});
    assertThrows(
        AwsCryptoException.class,
        "Ciphertext encrypted data keys exceed maxEncryptedDataKeys",
        () -> new ParsedCiphertext(result.getResult(), 3));
  }

  @Test
  public void noMaxEdks() {
    MasterKeyProvider<?> provider = providerWithEdks(MESSAGE_FORMAT_MAX_EDKS);
    CryptoResult<byte[], ?> result = encryptionClient_.encryptData(provider, new byte[] {1});

    // explicit no-max
    ParsedCiphertext ciphertext =
        new ParsedCiphertext(result.getResult(), CiphertextHeaders.NO_MAX_ENCRYPTED_DATA_KEYS);
    assertEquals(ciphertext.getEncryptedKeyBlobCount(), MESSAGE_FORMAT_MAX_EDKS);

    // implicit no-max
    ciphertext = new ParsedCiphertext(result.getResult());
    assertEquals(ciphertext.getEncryptedKeyBlobCount(), MESSAGE_FORMAT_MAX_EDKS);
  }
}
