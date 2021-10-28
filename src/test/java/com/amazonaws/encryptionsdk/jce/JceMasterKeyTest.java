package com.amazonaws.encryptionsdk.jce;

import java.security.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public class JceMasterKeyTest {

  private static final SecretKey SECRET_KEY = new SecretKeySpec(new byte[1], "AES");
  private static final PrivateKey PRIVATE_KEY;
  private static final PublicKey PUBLIC_KEY;

  static {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      PUBLIC_KEY = keyPair.getPublic();
      PRIVATE_KEY = keyPair.getPrivate();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private JceMasterKey jceGetInstance(final String algorithmName) {
    return JceMasterKey.getInstance(SECRET_KEY, "mockProvider", "mockKey", algorithmName);
  }

  private JceMasterKey jceGetInstanceAsymmetric(final String algorithmName) {
    return JceMasterKey.getInstance(
        PUBLIC_KEY, PRIVATE_KEY, "mockProvider", "mockKey", algorithmName);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGetInstanceInvalidWrappingAlgorithm() {
    jceGetInstance("blatently/unsupported/algorithm");
  }

  @Test(expected = UnsupportedOperationException.class)
  public void testGetInstanceAsymmetricInvalidWrappingAlgorithm() {
    jceGetInstanceAsymmetric("rsa/ec/unsupportedAlgorithm");
  }

  /**
   * Calls JceMasterKey.getInstance with differently cased wrappingAlgorithm names. Passes if no
   * Exception is thrown. Relies on passing an invalid algorithm name to result in an Exception.
   */
  @Test
  public void testGetInstanceAllLowercase() {
    jceGetInstance("aes/gcm/nopadding");
  }

  @Test
  public void testGetInstanceMixedCasing() {
    jceGetInstance("AES/GCm/NOpadding");
  }

  @Test
  public void testGetInstanceAsymmetricAllLowercase() {
    jceGetInstanceAsymmetric("rsa/ecb/oaepwithsha-256andmgf1padding");
  }

  @Test
  public void testGetInstanceAsymmetricMixedCasing() {
    jceGetInstanceAsymmetric("RSA/ECB/OAepwithsha-256andmgf1padding");
  }
}
