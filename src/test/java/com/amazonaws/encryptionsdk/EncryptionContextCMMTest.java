package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static com.amazonaws.encryptionsdk.kms.KMSTestFixtures.TEST_KEYSTORE_KMS_KEY_ID;
import static com.amazonaws.encryptionsdk.kms.KMSTestFixtures.TEST_KEYSTORE_NAME;
import static com.amazonaws.encryptionsdk.kms.KMSTestFixtures.TEST_LOGICAL_KEYSTORE_NAME;

import com.amazonaws.crypto.examples.keyrings.RawAesKeyringExample;
import com.amazonaws.crypto.examples.keyrings.RawRsaKeyringExample;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CacheType;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.DefaultCache;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.PaddingScheme;

public class EncryptionContextCMMTest {
  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);
  MaterialProviders matProv;

  @Before
  public void setUp() {
    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();

    matProv = MaterialProviders.builder().MaterialProvidersConfig(config).build();
  }

  @Test
  public void TestReprEncryptionContextWithSameECHappyCase() {
    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // HAPPY CASE 1
    // Test supply same encryption context on encrypt and decrypt NO filtering
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);

    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(multiKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA
    CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(rsaKeyring, ciphertext, encryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test KMS
    decryptResult = crypto.decryptData(rsaKeyring, ciphertext, encryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test AES
    decryptResult = crypto.decryptData(aesKeyring, ciphertext, encryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test Hierarchy Keyring
    decryptResult = crypto.decryptData(hKeyring, ciphertext, encryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void TestRemoveOnEncryptAndSupplyOnDecryptHappyCase() {
    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // Happy Test Case 2
    // On Encrypt we will only write one encryption context key value to the header
    // we will then supply only what we didn't write wth no required ec cmm,
    // This test case is checking that the default cmm is doing the correct filtering by using
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    final Map<String, String> reproducedEncryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.A);
    // These keys mean that we will not write these on the message but are required for message
    // authentication on decrypt.
    final List<String> requiredECKeys =
        Fixtures.generateEncryptionContextKeys(Fixtures.Variation.A);

    final ICryptographicMaterialsManager defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder()
                .keyring(multiKeyring)
                .build());
    final ICryptographicMaterialsManager reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());

    // Encrypt with Required Encryption Context CMM
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(reqCMM, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA
    CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(rsaKeyring, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test KMS
    decryptResult = crypto.decryptData(rsaKeyring, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test AES
    decryptResult = crypto.decryptData(aesKeyring, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test Hierarchy Keyring
    decryptResult = crypto.decryptData(hKeyring, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void TestRemoveOnEncryptRemoveAndSupplyOnDecryptHappyCase() {
    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // HAPPY CASE 3
    // On Encrypt we will only write one encryption context key value to the header
    // we will then supply only what we didn't write but included in the signature while we
    // are configured with the required encryption context cmm
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    final Map<String, String> reproducedEncryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.A);
    // These keys mean that we will not write these on the message but are required for message
    // authentication on decrypt.
    final List<String> requiredECKeys =
        Fixtures.generateEncryptionContextKeys(Fixtures.Variation.A);

    // Create Required EC CMM with the required EC Keys we want
    ICryptographicMaterialsManager defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder()
                .keyring(multiKeyring)
                .build());
    ICryptographicMaterialsManager reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());

    // Encrypt with Required Encryption Context CMM
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(reqCMM, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(rsaKeyring).build());
    reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test KMS
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(kmsKeyring).build());
    reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    decryptResult = crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test AES
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(aesKeyring).build());
    reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    decryptResult = crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test Hierarchy Keyring
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(hKeyring).build());
    reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    decryptResult = crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void TestRemoveOnDecryptIsBackwardsCompatibleHappyCase() {
    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // HAPPY CASE 4
    // On Encrypt we write all encryption context
    // as if the message was encrypted before the feature existed.
    // We will then have a required encryption context cmm
    // that will require us to supply the encryption context on decrypt.
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    final Map<String, String> reproducedEncryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.A);
    // These keys mean that we will not write these on the message but are required for message
    // authentication on decrypt.
    final List<String> requiredECKeys =
        Fixtures.generateEncryptionContextKeys(Fixtures.Variation.A);

    // Create Default CMM
    ICryptographicMaterialsManager defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder()
                .keyring(multiKeyring)
                .build());

    // Encrypt with Required Encryption Context CMM
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(defaultCMM, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(rsaKeyring).build());
    ICryptographicMaterialsManager reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    CryptoResult<byte[], ?> decryptResult =
        crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test KMS
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(kmsKeyring).build());
    reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    decryptResult = crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test AES
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(aesKeyring).build());
    reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    decryptResult = crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Test Hierarchy Keyring
    defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(hKeyring).build());
    reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());
    decryptResult = crypto.decryptData(reqCMM, ciphertext, reproducedEncryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  @Test
  public void TestDifferentECOnDecryptFailure() {
    // encrypt {a, b} => decrypt {b:c} => fail
    // encrypt {a, b} => decrypt {d} => fail

    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // FAILURE CASE 1
    // Encrypt with and store all encryption context in header
    // On Decrypt supply additional encryption context not stored in the header; this MUST fail
    // On Decrypt supply mismatched encryption context key values; this MUST fail
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    // Additional EC
    final Map<String, String> reproducedAdditionalEncryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.C);
    // Mismatched EncryptionContext
    final Map<String, String> reproducedMismatchedEncryptionContext =
        Fixtures.generateMismatchedEncryptionContext(Fixtures.Variation.AB);

    // Encrypt with Multi Keyring
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(multiKeyring, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(rsaKeyring, ciphertext, reproducedAdditionalEncryptionContext));
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(rsaKeyring, ciphertext, reproducedMismatchedEncryptionContext));

    // Test KMS Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(kmsKeyring, ciphertext, reproducedAdditionalEncryptionContext));
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(kmsKeyring, ciphertext, reproducedMismatchedEncryptionContext));

    // Test AES Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(aesKeyring, ciphertext, reproducedAdditionalEncryptionContext));
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(aesKeyring, ciphertext, reproducedMismatchedEncryptionContext));

    // Test Hierarchy Keyring Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(hKeyring, ciphertext, reproducedAdditionalEncryptionContext));
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(hKeyring, ciphertext, reproducedMismatchedEncryptionContext));
  }

  @Test
  public void TestRemoveECAndNotSupplyOnDecryptFailure() {
    // encrypt remove(a) RSA {a, b} => decrypt => fail
    // encrypt remove(a) KMS {a, b} => decrypt => fail
    // encrypt remove(a) AES {a, b} => decrypt => fail
    // encrypt remove(a) Hie {a, b} => decrypt => fail

    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // FAILURE CASE 2
    // Encrypt will not store all Encryption Context, we will drop one entry but it will still get
    // included in the
    // header signture.
    // Decrypt will not supply any reproduced Encryption Context; this MUST fail.
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    // These keys mean that we will not write these on the message but are required for message
    // authentication on decrypt.
    final List<String> requiredECKeys =
        Fixtures.generateEncryptionContextKeys(Fixtures.Variation.A);

    // Create Required EC CMM with the required EC Keys we want
    final ICryptographicMaterialsManager defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder()
                .keyring(multiKeyring)
                .build());
    final ICryptographicMaterialsManager reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());

    // Encrypt with Multi Keyring
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(reqCMM, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA Failure
    assertThrows(RuntimeException.class, () -> crypto.decryptData(rsaKeyring, ciphertext));

    // Test KMS Failure
    assertThrows(RuntimeException.class, () -> crypto.decryptData(kmsKeyring, ciphertext));

    // Test AES Failure
    assertThrows(RuntimeException.class, () -> crypto.decryptData(aesKeyring, ciphertext));

    // Test Hierarchy Keyring Failure
    assertThrows(RuntimeException.class, () -> crypto.decryptData(hKeyring, ciphertext));
  }

  @Test
  public void TestRemoveECAndSupplyMismatchedReprECFailure() {
    // encrypt remove(a) RSA {a, b} => decrypt {a:c} => fail
    // encrypt remove(a) KMS {a, b} => decrypt {a:c} => fail
    // encrypt remove(a) AES {a, b} => decrypt {a:c} => fail
    // encrypt remove(a) Hie {a, b} => decrypt {a:c} => fail

    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // Get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // FAILURE CASE 3
    // Encrypt will not store all Encryption Context, we will drop one entry but it will still get
    // included in the
    // header signture.
    // Decrypt will supply the correct key but incorrect value; this MUST fail.
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    // These keys mean that we will not write these on the message but are required for message
    // authentication on decrypt.
    final List<String> requiredECKeys =
        Fixtures.generateEncryptionContextKeys(Fixtures.Variation.A);
    // this reproduced encryption context contains the key we didn't store, but it has the wrong
    // value
    final Map<String, String> mismatchedReproducedEncryptionContext =
        Fixtures.generateMismatchedEncryptionContext(Fixtures.Variation.A);

    // Create Required EC CMM with the required EC Keys we want
    final ICryptographicMaterialsManager defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder()
                .keyring(multiKeyring)
                .build());
    final ICryptographicMaterialsManager reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());

    // Encrypt with Multi Keyring
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(reqCMM, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(rsaKeyring, ciphertext, mismatchedReproducedEncryptionContext));

    // Test KMS Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(kmsKeyring, ciphertext, mismatchedReproducedEncryptionContext));

    // Test AES Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(aesKeyring, ciphertext, mismatchedReproducedEncryptionContext));

    // Test Hierarchy Keyring Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(hKeyring, ciphertext, mismatchedReproducedEncryptionContext));
  }

  @Test
  public void TestRemoveECAndSupplyWithMissingRequiredValueDecryptFailure() {
    // encrypt remove(a) RSA {a, b} => decrypt remove(a) => fail
    // encrypt remove(a) KMS {a, b} => decrypt remove(a) => fail
    // encrypt remove(a) AES {a, b} => decrypt remove(a) => fail
    // encrypt remove(a) Hie {a, b} => decrypt remove(a) => fail

    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // Get keyrings
    final IKeyring rsaKeyring = getRsaKeyring();
    final IKeyring kmsKeyring = getAwsKmsKeyring();
    final IKeyring aesKeyring = getAesKeyring();
    final IKeyring hKeyring = getHierarchicalKeyring();

    final IKeyring multiKeyring =
        matProv.CreateMultiKeyring(
            CreateMultiKeyringInput.builder()
                .generator(aesKeyring)
                .childKeyrings(Arrays.asList(kmsKeyring, rsaKeyring, hKeyring))
                .build());

    // FAILURE CASE 4
    // Encrypt will not store all Encryption Context, we will drop one entry but it will still get
    // included in the
    // header signture.
    // Decrypt will supply the correct key but incorrect value; this MUST fail.
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    // These keys mean that we will not write these on the message but are required for message
    // authentication on decrypt.
    final List<String> requiredECKeys =
        Fixtures.generateEncryptionContextKeys(Fixtures.Variation.A);
    // this reproduced encryption context does not contain the key that was dropped
    final Map<String, String> droppedRequiredKeyEncryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.B);

    // Create Required EC CMM with the required EC Keys we want
    final ICryptographicMaterialsManager defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder()
                .keyring(multiKeyring)
                .build());
    final ICryptographicMaterialsManager reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());

    // Encrypt with Multi Keyring
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(reqCMM, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();

    // Test RSA Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(rsaKeyring, ciphertext, droppedRequiredKeyEncryptionContext));

    // Test KMS Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(kmsKeyring, ciphertext, droppedRequiredKeyEncryptionContext));

    // Test AES Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(aesKeyring, ciphertext, droppedRequiredKeyEncryptionContext));

    // Test Hierarchy Keyring Failure
    assertThrows(
        RuntimeException.class,
        () -> crypto.decryptData(hKeyring, ciphertext, droppedRequiredKeyEncryptionContext));
  }

  @Test
  public void TestReservedEncryptionContextKeyFailure() {
    // Instantiate the Client
    final AwsCrypto crypto = AwsCrypto.builder().build();

    // Get keyring
    final IKeyring rsaKeyring = getRsaKeyring();

    // FAILURE CASE 5
    // Although we are requesting that we remove a RESERVED key word from the encryption context
    // The CMM instantiation will still succeed because the CMM is meant to work with different
    // higher level
    // encryption libraries who may have different reserved keys. Encryption will ultimately fail.
    final Map<String, String> encryptionContext = Fixtures.getReservedEncryptionContextMap();
    final List<String> requiredECKeys = Fixtures.getReservedEncryptionContextKey();

    // Create Required EC CMM with the required EC Keys we want
    final ICryptographicMaterialsManager defaultCMM =
        matProv.CreateDefaultCryptographicMaterialsManager(
            CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(rsaKeyring).build());
    // Create Required EC CMM with the required EC Keys we want
    final ICryptographicMaterialsManager reqCMM =
        matProv.CreateRequiredEncryptionContextCMM(
            CreateRequiredEncryptionContextCMMInput.builder()
                .underlyingCMM(defaultCMM)
                .requiredEncryptionContextKeys(requiredECKeys)
                .build());

    // Encrypt with Multi Keyring
    assertThrows(
        RuntimeException.class, () -> crypto.encryptData(reqCMM, EXAMPLE_DATA, encryptionContext));
  }

  @Test
  public void TestReproducedEncryptionContextOnDecrypt() {
    final AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    // Get Keyring
    IKeyring rsaKeyring = getRsaKeyring();

    // Encryption Context
    final Map<String, String> encryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.A);
    // Additional EC
    final Map<String, String> reproducedAdditionalEncryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.C);
    // Incorrect EncryptionContext
    final Map<String, String> reproducedIncorrectEncryptionContext =
        Fixtures.generateEncryptionContext(Fixtures.Variation.AB);
    // Mismatched EncryptionContext
    final Map<String, String> reproducedMismatchedEncryptionContext =
        Fixtures.generateMismatchedEncryptionContext(Fixtures.Variation.AB);

    // Encrypt the data
    final CryptoResult<byte[], ?> encryptResult =
        crypto.encryptData(rsaKeyring, EXAMPLE_DATA, encryptionContext);

    final byte[] ciphertext = encryptResult.getResult();

    // Decrypt the data
    // We expect to fail because we use different encryption context than the one we used on
    // encrypt.
    Assert.assertThrows(
        Exception.class,
        () -> crypto.decryptData(rsaKeyring, ciphertext, reproducedAdditionalEncryptionContext));

    // Decrypt the data
    // We expect to fail because we pass more encryption context than was used on encrypt
    assertThrows(
        Exception.class,
        () -> crypto.decryptData(rsaKeyring, ciphertext, reproducedIncorrectEncryptionContext));

    // Decrypt the data
    // We expect to fail because although the same key is present on the ec
    // their value is different.
    Assert.assertThrows(
        Exception.class,
        () -> crypto.decryptData(rsaKeyring, ciphertext, reproducedMismatchedEncryptionContext));

    // Decrypt the data & Verify that the decrypted plaintext matches the original plaintext
    // Since we store all encryption context we MUST succeed if no encryption context is
    // supplied on decrypt
    CryptoResult<byte[], ?> decryptResult = crypto.decryptData(rsaKeyring, ciphertext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);

    // Decrypt the data & Verify that the decrypted plaintext matches the original plaintext
    decryptResult = crypto.decryptData(rsaKeyring, ciphertext, encryptionContext);
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }

  private IKeyring getRsaKeyring() {
    final KeyPair keyPair = RawRsaKeyringExample.generateKeyPair();
    final ByteBuffer publicKeyBytes = RawRsaKeyringExample.getPEMPublicKey(keyPair.getPublic());
    final ByteBuffer privateKeyBytes = RawRsaKeyringExample.getPEMPrivateKey(keyPair.getPrivate());

    final CreateRawRsaKeyringInput encryptingKeyringInput =
        CreateRawRsaKeyringInput.builder()
            .keyName("rsa-key")
            .keyNamespace("rsa-keyring")
            .paddingScheme(PaddingScheme.PKCS1)
            .publicKey(publicKeyBytes)
            .privateKey(privateKeyBytes)
            .build();
    return matProv.CreateRawRsaKeyring(encryptingKeyringInput);
  }

  private IKeyring getAesKeyring() {
    final ByteBuffer aesKeyBytes = RawAesKeyringExample.generateAesKeyBytes();
    final CreateRawAesKeyringInput keyringInput =
        CreateRawAesKeyringInput.builder()
            .keyName("my-aes-key-name")
            .keyNamespace("my-key-namespace")
            .wrappingKey(aesKeyBytes)
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build();
    return matProv.CreateRawAesKeyring(keyringInput);
  }

  private IKeyring getAwsKmsKeyring() {
    final String keyArn = KMSTestFixtures.US_WEST_2_KEY_ID;
    final CreateAwsKmsKeyringInput keyringInput =
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn).kmsClient(KmsClient.create()).build();
    return matProv.CreateAwsKmsKeyring(keyringInput);
  }

  private IKeyring getHierarchicalKeyring() {
    final String keyStoreTableName = TEST_KEYSTORE_NAME;
    final String logicalKeyStoreName = TEST_LOGICAL_KEYSTORE_NAME;
    final String kmsKeyId = TEST_KEYSTORE_KMS_KEY_ID;

    final KeyStore keystore =
        KeyStore.builder()
            .KeyStoreConfig(
                KeyStoreConfig.builder()
                    .ddbClient(DynamoDbClient.create())
                    .ddbTableName(keyStoreTableName)
                    .logicalKeyStoreName(logicalKeyStoreName)
                    .kmsClient(KmsClient.create())
                    .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(kmsKeyId).build())
                    .build())
            .build();

    final String branchKeyId =
        keystore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();

    final CreateAwsKmsHierarchicalKeyringInput keyringInput =
        CreateAwsKmsHierarchicalKeyringInput.builder()
            .keyStore(keystore)
            .branchKeyId(branchKeyId)
            .ttlSeconds(600)
            .cache(
                CacheType.builder() // OPTIONAL
                    .Default(DefaultCache.builder().entryCapacity(100).build())
                    .build())
            .build();
    return matProv.CreateAwsKmsHierarchicalKeyring(keyringInput);
  }
}
