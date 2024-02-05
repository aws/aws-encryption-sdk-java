package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.Before;
import org.junit.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.PaddingScheme;

public class AwsCryptoIntegrationTest {

  private static SecretKey AES_KEY;
  private static KeyPair RSA_KEY_PAIR;
  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  @Before
  public void setUp() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    AES_KEY = keyGen.generateKey();

    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    RSA_KEY_PAIR = keyPairGen.generateKeyPair();
  }

  @Test
  public void AwsKmsEncryptDecryptMasterKey() {

    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    KmsMasterKeyProvider keyProvider =
        KmsMasterKeyProvider.builder().buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], KmsMasterKey> encryptResult =
        crypto.encryptData(keyProvider, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], KmsMasterKey> decryptResult =
        crypto.decryptData(keyProvider, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void AwsKmsEncryptDecryptKeyring() {
    // Instantiate the SDK
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    // Create a AwsKmsKeyring
    CreateAwsKmsKeyringInput nativeValue =
        CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(KMSTestFixtures.TEST_KEY_IDS[0])
            .kmsClient(KmsClient.create())
            .build();
    IKeyring kmsKeyring = materialProviders.CreateAwsKmsKeyring(nativeValue);

    // Create an encryption context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(kmsKeyring, EXAMPLE_DATA, encryptionContext);

    List<?> masterKeys = encryptResult.getMasterKeys();
    List<String> masterKeyIds = encryptResult.getMasterKeyIds();
    // Assert CryptoResult returns empty list if keyrings are used.
    assert masterKeys.isEmpty();
    assert masterKeyIds.isEmpty();

    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(kmsKeyring, ciphertext, encryptionContext);
    masterKeys = decryptResult.getMasterKeys();
    masterKeyIds = decryptResult.getMasterKeyIds();
    // Assert CryptoResult returns empty list if keyrings are used.
    assert masterKeys.isEmpty();
    assert masterKeyIds.isEmpty();

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void AwsKmsEncryptMasterKeyDecryptKeyring() {
    // Instantiate the SDK
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    KmsMasterKeyProvider keyProvider =
        KmsMasterKeyProvider.builder().buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    CreateAwsKmsKeyringInput nativeValue =
        CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(KMSTestFixtures.TEST_KEY_IDS[0])
            .kmsClient(KmsClient.create())
            .build();
    IKeyring kmsKeyring = materialProviders.CreateAwsKmsKeyring(nativeValue);

    // Create an encryption context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], KmsMasterKey> encryptResult =
        crypto.encryptData(keyProvider, EXAMPLE_DATA, encryptionContext);

    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], ?> decryptResult = crypto.decryptData(kmsKeyring, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void AwsKmsEncryptKeyringDecryptMasterKey() {
    // Instantiate the SDK
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    KmsMasterKeyProvider keyProvider =
        KmsMasterKeyProvider.builder().buildStrict(KMSTestFixtures.TEST_KEY_IDS[0]);

    CreateAwsKmsKeyringInput nativeValue =
        CreateAwsKmsKeyringInput.builder()
            .kmsKeyId(KMSTestFixtures.TEST_KEY_IDS[0])
            .kmsClient(KmsClient.create())
            .build();
    IKeyring kmsKeyring = materialProviders.CreateAwsKmsKeyring(nativeValue);

    // Create an encryption context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(kmsKeyring, EXAMPLE_DATA, encryptionContext);

    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], KmsMasterKey> decryptResult =
        crypto.decryptData(keyProvider, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawAesEncryptDecryptMasterKey() {

    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    final JceMasterKey masterKey =
        JceMasterKey.getInstance(
            AES_KEY, "aws-raw-vectors-persistant", "aes-key", "AES/GCM/NoPadding");

    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], JceMasterKey> encryptResult =
        crypto.encryptData(masterKey, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], JceMasterKey> decryptResult =
        crypto.decryptData(masterKey, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawAesEncryptMasterKeyDecryptKeyring() {
    // AWS Encryption SDK Client
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    // Keyring
    IKeyring keyring =
        materialProviders.CreateRawAesKeyring(
            CreateRawAesKeyringInput.builder()
                .keyName("aes-key")
                .keyNamespace("aws-raw-vectors-persistant")
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .wrappingKey(ByteBuffer.wrap(AES_KEY.getEncoded()))
                .build());

    // MasterKey
    final JceMasterKey masterKey =
        JceMasterKey.getInstance(
            AES_KEY, "aws-raw-vectors-persistant", "aes-key", "AES/GCM/NoPadding");

    // Encryption Context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], JceMasterKey> encryptResult =
        crypto.encryptData(masterKey, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], ?> decryptResult = crypto.decryptData(keyring, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawAesEncryptKeyringKeyDecryptMasterKey() {
    // AWS Encryption SDK Client
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    // Keyring
    IKeyring keyring =
        materialProviders.CreateRawAesKeyring(
            CreateRawAesKeyringInput.builder()
                .keyName("aes-key")
                .keyNamespace("aws-raw-vectors-persistant")
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .wrappingKey(ByteBuffer.wrap(AES_KEY.getEncoded()))
                .build());

    // MasterKey
    final JceMasterKey masterKey =
        JceMasterKey.getInstance(
            AES_KEY, "aws-raw-vectors-persistant", "aes-key", "AES/GCM/NoPadding");

    // Encryption Context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], JceMasterKey> decryptResult =
        crypto.decryptData(masterKey, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawAesEncryptDecryptKeyring() {
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    IKeyring keyring =
        materialProviders.CreateRawAesKeyring(
            CreateRawAesKeyringInput.builder()
                .keyName("aes-key")
                .keyNamespace("aws-raw-vectors-persistant")
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .wrappingKey(ByteBuffer.wrap(AES_KEY.getEncoded()))
                .build());

    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], ?> decryptResult = crypto.decryptData(keyring, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawRsaEncryptDecryptMasterKey() throws Exception {
    // AWS Encryption SDK Client
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    // MasterKey
    final JceMasterKey masterKey =
        JceMasterKey.getInstance(
            RSA_KEY_PAIR.getPublic(),
            RSA_KEY_PAIR.getPrivate(),
            "rsa-keyring",
            "rsa-key",
            "RSA/ECB/PKCS1Padding");
    // Encryption Context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], JceMasterKey> encryptResult =
        crypto.encryptData(masterKey, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], JceMasterKey> decryptResult =
        crypto.decryptData(masterKey, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawRsaEncryptMasterKeyDecryptKeyring() throws Exception {
    // AWS Encryption SDK Client
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    // Keyring
    IKeyring keyring =
        materialProviders.CreateRawRsaKeyring(
            CreateRawRsaKeyringInput.builder()
                .keyName("rsa-key")
                .keyNamespace("rsa-keyring")
                .paddingScheme(PaddingScheme.PKCS1)
                .privateKey(getPEMPrivateKey(RSA_KEY_PAIR.getPrivate()))
                .build());

    // MasterKey
    final JceMasterKey masterKey =
        JceMasterKey.getInstance(
            RSA_KEY_PAIR.getPublic(), null, "rsa-keyring", "rsa-key", "RSA/ECB/PKCS1Padding");
    // Encryption Context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], JceMasterKey> encryptResult =
        crypto.encryptData(masterKey, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], ?> decryptResult = crypto.decryptData(keyring, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawRsaEncryptKeyringKeyDecryptMasterKey() throws Exception {
    // AWS Encryption SDK Client
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    // Keyring
    IKeyring keyring =
        materialProviders.CreateRawRsaKeyring(
            CreateRawRsaKeyringInput.builder()
                .keyName("rsa-key")
                .keyNamespace("rsa-keyring")
                .paddingScheme(PaddingScheme.PKCS1)
                .publicKey(getPEMPublicKey(RSA_KEY_PAIR.getPublic()))
                .build());

    // MasterKey
    final JceMasterKey masterKey =
        JceMasterKey.getInstance(
            null, RSA_KEY_PAIR.getPrivate(), "rsa-keyring", "rsa-key", "RSA/ECB/PKCS1Padding");

    // Encryption Context
    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], JceMasterKey> decryptResult =
        crypto.decryptData(masterKey, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void RawRsaEncryptDecryptKeyring() throws Exception {
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();

    IKeyring keyring =
        materialProviders.CreateRawRsaKeyring(
            CreateRawRsaKeyringInput.builder()
                .keyName("rsa-key")
                .keyNamespace("rsa-keyring")
                .paddingScheme(PaddingScheme.PKCS1)
                .publicKey(getPEMPublicKey(RSA_KEY_PAIR.getPublic()))
                .privateKey(getPEMPrivateKey(RSA_KEY_PAIR.getPrivate()))
                .build());

    final Map<String, String> encryptionContext =
        Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    final CryptoResult<byte[], ?> decryptResult = crypto.decryptData(keyring, ciphertext);

    // Verify that the encryption context in the result contains the
    // encryption context supplied to the encryptData method.
    if (!encryptionContext.entrySet().stream()
        .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }

    // Verify that the decrypted plaintext matches the original plaintext
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
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
