package com.amazonaws.encryptionsdk.multi;

import static com.amazonaws.encryptionsdk.internal.RandomBytesGenerator.generate;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public class MultipleMasterKeyTest {
  private static final String WRAPPING_ALG = "AES/GCM/NoPadding";
  private static final byte[] PLAINTEXT = generate(1024);

  @Test
  public void testMultipleJceKeys() {
    final SecretKeySpec k1 = new SecretKeySpec(generate(32), "AES");
    final JceMasterKey mk1 = JceMasterKey.getInstance(k1, "jce", "1", WRAPPING_ALG);
    final SecretKeySpec k2 = new SecretKeySpec(generate(32), "AES");
    final JceMasterKey mk2 = JceMasterKey.getInstance(k2, "jce", "2", WRAPPING_ALG);
    final MasterKeyProvider<JceMasterKey> mkp =
        MultipleProviderFactory.buildMultiProvider(JceMasterKey.class, mk1, mk2);

    AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    CryptoResult<byte[], JceMasterKey> ct = crypto.encryptData(mkp, PLAINTEXT);
    assertEquals(2, ct.getMasterKeyIds().size());
    CryptoResult<byte[], JceMasterKey> result = crypto.decryptData(mkp, ct.getResult());
    assertArrayEquals(PLAINTEXT, result.getResult());
    // Only the first found key should be used
    assertEquals(1, result.getMasterKeys().size());
    assertEquals(mk1, result.getMasterKeys().get(0));

    assertMultiReturnsKeys(mkp, mk1, mk2);
  }

  @Test
  public void testMultipleJceKeysSingleDecrypt() {
    final SecretKeySpec k1 = new SecretKeySpec(generate(32), "AES");
    final JceMasterKey mk1 = JceMasterKey.getInstance(k1, "jce", "1", WRAPPING_ALG);
    final SecretKeySpec k2 = new SecretKeySpec(generate(32), "AES");
    final JceMasterKey mk2 = JceMasterKey.getInstance(k2, "jce", "2", WRAPPING_ALG);
    final MasterKeyProvider<JceMasterKey> mkp =
        MultipleProviderFactory.buildMultiProvider(JceMasterKey.class, mk1, mk2);

    AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    CryptoResult<byte[], JceMasterKey> ct = crypto.encryptData(mkp, PLAINTEXT);
    assertEquals(2, ct.getMasterKeyIds().size());

    CryptoResult<byte[], JceMasterKey> result = crypto.decryptData(mk1, ct.getResult());
    assertArrayEquals(PLAINTEXT, result.getResult());
    // Only the first found key should be used
    assertEquals(1, result.getMasterKeys().size());
    assertEquals(mk1, result.getMasterKeys().get(0));

    result = crypto.decryptData(mk2, ct.getResult());
    assertArrayEquals(PLAINTEXT, result.getResult());
    // Only the first found key should be used
    assertEquals(1, result.getMasterKeys().size());
    assertEquals(mk2, result.getMasterKeys().get(0));
  }

  @Test
  public void testMixedKeys() {
    final SecretKeySpec k1 = new SecretKeySpec(generate(32), "AES");
    final JceMasterKey mk1 = JceMasterKey.getInstance(k1, "jce", "1", WRAPPING_ALG);
    StaticMasterKey mk2 = new StaticMasterKey("mock1");
    final MasterKeyProvider<?> mkp = MultipleProviderFactory.buildMultiProvider(mk1, mk2);

    AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    CryptoResult<byte[], ?> ct = crypto.encryptData(mkp, PLAINTEXT);
    assertEquals(2, ct.getMasterKeyIds().size());
    CryptoResult<byte[], ?> result = crypto.decryptData(mkp, ct.getResult());
    assertArrayEquals(PLAINTEXT, result.getResult());
    // Only the first found key should be used
    assertEquals(1, result.getMasterKeys().size());
    assertEquals(mk1, result.getMasterKeys().get(0));

    assertMultiReturnsKeys(mkp, mk1, mk2);
  }

  @Test
  public void testMixedKeysSingleDecrypt() {
    final SecretKeySpec k1 = new SecretKeySpec(generate(32), "AES");
    final JceMasterKey mk1 = JceMasterKey.getInstance(k1, "jce", "1", WRAPPING_ALG);
    StaticMasterKey mk2 = new StaticMasterKey("mock1");

    final MasterKeyProvider<?> mkp = MultipleProviderFactory.buildMultiProvider(mk1, mk2);

    AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    CryptoResult<byte[], ?> ct = crypto.encryptData(mkp, PLAINTEXT);
    assertEquals(2, ct.getMasterKeyIds().size());

    CryptoResult<byte[], ?> result = crypto.decryptData(mk1, ct.getResult());
    assertArrayEquals(PLAINTEXT, result.getResult());
    // Only the first found key should be used
    assertEquals(1, result.getMasterKeys().size());
    assertEquals(mk1, result.getMasterKeys().get(0));

    result = crypto.decryptData(mk2, ct.getResult());
    assertArrayEquals(PLAINTEXT, result.getResult());
    // Only the first found key should be used
    assertEquals(1, result.getMasterKeys().size());
    assertEquals(mk2, result.getMasterKeys().get(0));
  }

  private void assertMultiReturnsKeys(MasterKeyProvider<?> mkp, MasterKey<?>... mks) {
    for (MasterKey<?> mk : mks) {
      assertEquals(mk, mkp.getMasterKey(mk.getKeyId()));
      assertEquals(mk, mkp.getMasterKey(mk.getProviderId(), mk.getKeyId()));
    }
  }
}
