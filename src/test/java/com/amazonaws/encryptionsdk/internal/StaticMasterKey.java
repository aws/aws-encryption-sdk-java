package com.amazonaws.encryptionsdk.internal;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Static implementation of the {@link MasterKey} interface that should only used for unit-tests.
 *
 * <p>Contains a statically defined asymmetric master key-pair that can be used to encrypt and
 * decrypt (randomly generated) symmetric data key.
 *
 * <p>
 *
 * @author patye
 */
@NotThreadSafe
public class StaticMasterKey extends MasterKey<StaticMasterKey> {
  private static final String PROVIDER_ID = "static_provider";

  /** Generates random strings that can be used to create data keys. */
  private static final SecureRandom SRAND = new SecureRandom();

  /** Encryption algorithm for the master key-pair */
  private static final String MASTER_KEY_ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";

  /** Encryption algorithm for the KeyFactory */
  private static final String MASTER_KEY_ALGORITHM = "RSA";

  /** Encryption algorithm for the randomly generated data key */
  private static final String DATA_KEY_ENCRYPTION_ALGORITHM = "AES";

  /** The ID of the master key */
  @Nonnull private String keyId_;

  /**
   * The {@link Cipher} object created with the public part of the master-key. It's used to encrypt
   * data keys.
   */
  @Nonnull private final Cipher masterKeyEncryptionCipher_;

  /**
   * The {@link Cipher} object created with the private part of the master-key. It's used to decrypt
   * encrypted data keys.
   */
  @Nonnull private final Cipher masterKeyDecryptionCipher_;

  /** Generates random data keys. */
  @Nonnull private KeyGenerator keyGenerator_;

  /**
   * Creates a new object that encrypts the data key with a master key whose id is {@code keyId}.
   *
   * <p>The value of {@code keyId} does not affect how the data key will be generated or encrypted.
   * The {@code keyId} forms part of the header of the encrypted data, and is used to ensure that
   * the header cannot be tempered with.
   */
  public StaticMasterKey(@Nonnull final String keyId) {
    this.keyId_ = Objects.requireNonNull(keyId);

    try {
      KeyFactory keyFactory = KeyFactory.getInstance(MASTER_KEY_ALGORITHM);
      KeySpec publicKeySpec = new X509EncodedKeySpec(publicKey_v1);
      PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
      KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey_v1);
      PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);

      masterKeyEncryptionCipher_ = Cipher.getInstance(MASTER_KEY_ENCRYPTION_ALGORITHM);
      masterKeyEncryptionCipher_.init(Cipher.ENCRYPT_MODE, pubKey);

      masterKeyDecryptionCipher_ = Cipher.getInstance(MASTER_KEY_ENCRYPTION_ALGORITHM);
      masterKeyDecryptionCipher_.init(Cipher.DECRYPT_MODE, privKey);

    } catch (GeneralSecurityException ex) {
      throw new RuntimeException(ex);
    }
  }

  /**
   * Changes the {@link #keyId_}. This method is expected to be used to test that header of an
   * encrypted message cannot be tempered with.
   */
  public void setKeyId(@Nonnull String keyId) {
    this.keyId_ = Objects.requireNonNull(keyId);
  }

  @Override
  public String getProviderId() {
    return PROVIDER_ID;
  }

  @Override
  public String getKeyId() {
    return keyId_;
  }

  @Override
  public DataKey<StaticMasterKey> generateDataKey(
      CryptoAlgorithm algorithm, Map<String, String> encryptionContext) {
    try {
      this.keyGenerator_ = KeyGenerator.getInstance(DATA_KEY_ENCRYPTION_ALGORITHM);
      this.keyGenerator_.init(algorithm.getDataKeyLength() * 8, SRAND);
      SecretKey key =
          new SecretKeySpec(keyGenerator_.generateKey().getEncoded(), algorithm.getDataKeyAlgo());
      byte[] encryptedKey = masterKeyEncryptionCipher_.doFinal(key.getEncoded());
      return new DataKey<>(key, encryptedKey, keyId_.getBytes(StandardCharsets.UTF_8), this);
    } catch (GeneralSecurityException ex) {
      throw new RuntimeException(ex);
    }
  }

  @Override
  public DataKey<StaticMasterKey> encryptDataKey(
      CryptoAlgorithm algorithm, Map<String, String> encryptionContext, DataKey<?> dataKey) {
    try {
      byte[] unencryptedKey = dataKey.getKey().getEncoded();
      byte[] encryptedKey = masterKeyEncryptionCipher_.doFinal(unencryptedKey);
      SecretKey newKey =
          new SecretKeySpec(dataKey.getKey().getEncoded(), algorithm.getDataKeyAlgo());
      return new DataKey<>(newKey, encryptedKey, keyId_.getBytes(StandardCharsets.UTF_8), this);
    } catch (GeneralSecurityException ex) {
      throw new RuntimeException(ex);
    }
  }

  @Override
  public DataKey<StaticMasterKey> decryptDataKey(
      CryptoAlgorithm algorithm,
      Collection<? extends EncryptedDataKey> encryptedDataKeys,
      Map<String, String> encryptionContext)
      throws UnsupportedProviderException, AwsCryptoException {
    try {
      for (EncryptedDataKey edk : encryptedDataKeys) {
        if (keyId_.equals(new String(edk.getProviderInformation(), StandardCharsets.UTF_8))) {
          byte[] unencryptedDataKey = masterKeyDecryptionCipher_.doFinal(edk.getEncryptedDataKey());
          SecretKey key = new SecretKeySpec(unencryptedDataKey, algorithm.getDataKeyAlgo());
          return new DataKey<>(key, edk.getEncryptedDataKey(), edk.getProviderInformation(), this);
        }
      }
    } catch (GeneralSecurityException ex) {
      throw new RuntimeException(ex);
    }
    return null;
  }

  /** Statically configured private key. */
  private static final byte[] privateKey_v1 =
      Utils.decodeBase64String(
          "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKLpwqjYtYExVilW/Hg0ogWv9xZ+"
              + "THj4IzvISLlPtK8W6KXMcqukfuxdYmndPv8UD1DbdHFYSSistdqoBN32vVQOQnJZyYm45i2TDOV0"
              + "M2DtHtR6aMMlBLGtdPeeaT88nQfI1ORjRDyR1byMwomvmKifZYga6FjLt/sgqfSE9BUnAgMBAAEC"
              + "gYAqnewGL2qLuVRIzDCPYXVg938zqyZmHsNYyDP+BhPGGcASX0FAFW/+dQ9hkjcAk0bOaBo17Fp3"
              + "AXcxE/Lx/bHY+GWZ0wOJfl3aJBVJOpW8J6kwu68BUCmuFtRgbLSFu5+fbey3pKafYSptbX1fAI+z"
              + "hTx+a9B8pnn79ad4ziJ2QQJBAM+YHPGAEbr5qcNkwyy0xZgR/TLlcW2NQUt8HZpmErdX6d328iBC"
              + "SPb8+whXxCXZC3Mr+35IZ1pxxf0go/zGQv0CQQDI5oH0z1CKxoT6ErswNzB0oHxq/wD5mhutyqHa"
              + "mxbG5G3fN7I2IclwaXEA2eutIKxFMQNZYsX5mNYsrveSKivzAkABiujUJpZ7JDXNvObyYxmAyslt"
              + "4mSYYs9UZ0S1DAMhl6amPpqIANYX98NJyZUsjtNV9MK2qoUSF/xXqDFvxG1lAkBhP5Ow2Zn3U1mT"
              + "Y/XQxSZjjjwr3vyt1neHjQsEMwa3iGPXJbLSmVBVZfUZoGOBDsvVQoCIiFOlGuKyBpA45MkZAkAH"
              + "ksUrS9xLrDIUOI2BzMNRsK0bH7KJ+PFxm2SBgJOF9+Uf2A9LIP4IvESZq+ufp6c8YaqgR6Id1vws"
              + "7rUyGoa5");

  /** Statically configured public key. */
  private static final byte[] publicKey_v1 =
      Utils.decodeBase64String(
          "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCi6cKo2LWBMVYpVvx4NKIFr/cWfkx4+CM7yEi5"
              + "T7SvFuilzHKrpH7sXWJp3T7/FA9Q23RxWEkorLXaqATd9r1UDkJyWcmJuOYtkwzldDNg7R7UemjD"
              + "JQSxrXT3nmk/PJ0HyNTkY0Q8kdW8jMKJr5ion2WIGuhYy7f7IKn0hPQVJwIDAQAB");
}
