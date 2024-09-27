// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static java.lang.String.format;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.encryptionsdk.internal.SignaturePolicy;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.AwsKmsMrkAwareMasterKeyProvider;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.util.IOUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Base64;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import software.amazon.awssdk.regions.Region;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviderstestvectorkeys.KeyVectors;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.GetKeyDescriptionInput;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.GetKeyDescriptionOutput;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.KeyVectorsConfig;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.TestVectorKeyringInput;

@RunWith(Parameterized.class)
public class TestVectorRunner {

  // TODO: Standardize Manifest Version
  private static final List<Integer> MANIFEST_VERSIONS = Arrays.asList(2, 4);

  // We save the files in memory to avoid repeatedly retrieving them. This won't work if the
  // plaintexts are too
  // large or numerous
  private static final Map<String, byte[]> cachedData = new HashMap<>();

  private final String testName;
  private final TestCase testCase;
  private final DecryptionMethod decryptionMethod;

  public TestVectorRunner(
      final String testName, TestCase testCase, DecryptionMethod decryptionMethod) {
    this.testName = testName;
    this.testCase = testCase;
    this.decryptionMethod = decryptionMethod;
  }

  @Test
  public void decrypt() throws Exception {
    AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
            .build();
    Callable<byte[]> decryptor;
    if (testCase.isKeyring) {
      decryptor =
          () ->
              decryptionMethod.decryptMessage(
                  crypto,
                  testCase.cmmSupplier.get(),
                  cachedData.get(testCase.ciphertextPath),
                  testCase.encryptionContext);
    } else {
      decryptor =
          () ->
              decryptionMethod.decryptMessage(
                  crypto, testCase.mkpSupplier.get(), cachedData.get(testCase.ciphertextPath));
    }
    testCase.matcher.Match(decryptor);
  }

  @Parameterized.Parameters(name = "Compatibility Test: {0} - {3}")
  @SuppressWarnings("unchecked")
  public static Collection<Object[]> data() throws Exception {
    final String zipPath = System.getProperty("testVectorZip");
    final String interfaceOption = System.getProperty("masterkey");
    if (zipPath == null) {
      return Collections.emptyList();
    }

    final JarURLConnection jarConnection =
        (JarURLConnection) new URL("jar:" + zipPath + "!/").openConnection();

    try (JarFile jar = jarConnection.getJarFile()) {

      final Map<String, Object> manifest = readJsonMapFromJar(jar, "manifest.json");
      final Map<String, Object> keysManifest = readJsonMapFromJar(jar, "keys.json");

      ObjectMapper objectMapper = new ObjectMapper();

      // Create a temporary file and write the JSON string to it
      File tempFile = File.createTempFile("keys", ".json");
      objectMapper.writeValue(tempFile, keysManifest);

      final Map<String, Object> metaData = (Map<String, Object>) manifest.get("manifest");

      // We only support "awses-decrypt" type manifests right now
      if (!"awses-decrypt".equals(metaData.get("type"))) {
        throw new IllegalArgumentException("Unsupported manifest type: " + metaData.get("type"));
      }
      Integer readVersion = (Integer) metaData.get("version");
      if (!MANIFEST_VERSIONS.contains(readVersion)) {
        throw new IllegalArgumentException(
            "Unsupported manifest version: " + metaData.get("version"));
      }

      final Map<String, KeyEntry> keys =
          parseKeyManifest(readJsonMapFromJar(jar, (String) manifest.get("keys")));

      KeyVectors keyVectors =
          KeyVectors.builder()
              .KeyVectorsConfig(
                  KeyVectorsConfig.builder().keyManifestPath(tempFile.getPath()).build())
              .build();

      MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
      MaterialProviders materialProviders =
          MaterialProviders.builder().MaterialProvidersConfig(config).build();

      final KmsMasterKeyProvider kmsProvV1 =
          KmsMasterKeyProvider.builder()
              .withCredentials(new DefaultAWSCredentialsProviderChain())
              .buildDiscovery();

      final com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider kmsProvV2 =
          com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider.builder().buildDiscovery();

      List<Object[]> testCases = new ArrayList<>();
      for (Map.Entry<String, Map<String, Object>> testEntry :
          ((Map<String, Map<String, Object>>) manifest.get("tests")).entrySet()) {
        if (interfaceOption != null && interfaceOption.equals("true")) {
          String testName = testEntry.getKey();

          TestCase testCaseV1 =
              parseTest(testEntry.getKey(), testEntry.getValue(), keys, jar, kmsProvV1);
          TestCase testCaseV2 =
              parseTest(testEntry.getKey(), testEntry.getValue(), keys, jar, kmsProvV2);

          for (DecryptionMethod decryptionMethod : DecryptionMethod.values()) {
            if (testCaseV1.signaturePolicy.equals(decryptionMethod.signaturePolicy())) {
              testCases.add(new Object[] {testName, testCaseV1, decryptionMethod});
              testCases.add(new Object[] {testName + "-V2", testCaseV2, decryptionMethod});
            }
          }
        } else {
          String testName = testEntry.getKey();
          TestCase testCaseKeyring =
              parseTest(
                  testEntry.getKey(),
                  testEntry.getValue(),
                  keys,
                  jar,
                  materialProviders,
                  keyVectors);

          for (DecryptionMethod decryptionMethod : DecryptionMethod.values()) {
            if (testCaseKeyring.signaturePolicy.equals(decryptionMethod.signaturePolicy())) {
              testCases.add(
                  new Object[] {testName + "-Keyrings", testCaseKeyring, decryptionMethod});
            }
          }
        }
      }
      return testCases;
    }
  }

  @AfterClass
  public static void teardown() {
    cachedData.clear();
  }

  private static byte[] readBytesFromJar(JarFile jar, String fileName) throws IOException {
    try (InputStream is = readFromJar(jar, fileName)) {
      return IOUtils.toByteArray(is);
    }
  }

  private static Map<String, Object> readJsonMapFromJar(JarFile jar, String fileName)
      throws IOException {
    try (InputStream is = readFromJar(jar, fileName)) {
      final ObjectMapper mapper = new ObjectMapper();
      return mapper.readValue(is, new TypeReference<Map<String, Object>>() {});
    }
  }

  private static InputStream readFromJar(JarFile jar, String name) throws IOException {
    // Our manifest URIs incorrectly start with file:// rather than just file: so we need to strip
    // this
    ZipEntry entry = jar.getEntry(name.replaceFirst("^file://(?!/)", ""));
    return jar.getInputStream(entry);
  }

  private static void cacheData(JarFile jar, String url) throws IOException {
    if (!cachedData.containsKey(url)) {
      cachedData.put(url, readBytesFromJar(jar, url));
    }
  }

  /** Parse Test to Keyring */
  @SuppressWarnings("unchecked")
  private static TestCase parseTest(
      String testName,
      Map<String, Object> data,
      Map<String, KeyEntry> keys,
      JarFile jar,
      MaterialProviders materialProviders,
      KeyVectors keyVectors)
      throws IOException {
    final String ciphertextURL = (String) data.get("ciphertext");
    cacheData(jar, ciphertextURL);

    Supplier<ICryptographicMaterialsManager> cmmSupplier =
        () -> {
          final List<IKeyring> keyrings = new ArrayList<>();
          for (Map<String, String> mkEntry : (List<Map<String, String>>) data.get("master-keys")) {
            if (mkEntry.get("type").equals("raw")
                && mkEntry.get("encryption-algorithm").equals("rsa")) {
              mkEntry.putIfAbsent("padding-hash", "sha1");
            }

            try {
              byte[] json = new ObjectMapper().writeValueAsBytes(mkEntry);
              GetKeyDescriptionOutput output =
                  keyVectors.GetKeyDescription(
                      GetKeyDescriptionInput.builder().json(ByteBuffer.wrap(json)).build());

              IKeyring testVectorKeyring =
                  keyVectors.CreateTestVectorKeyring(
                      TestVectorKeyringInput.builder()
                          .keyDescription(output.keyDescription())
                          .build());

              keyrings.add(testVectorKeyring);
            } catch (JsonProcessingException e) {
              throw new RuntimeException(e);
            }
          }

          IKeyring multiKeyring =
              materialProviders.CreateMultiKeyring(
                  CreateMultiKeyringInput.builder()
                      .generator(keyrings.get(0))
                      .childKeyrings(keyrings)
                      .build());

          CreateDefaultCryptographicMaterialsManagerInput defaultInput =
              CreateDefaultCryptographicMaterialsManagerInput.builder()
                  .keyring(multiKeyring)
                  .build();
          ICryptographicMaterialsManager cmm =
              materialProviders.CreateDefaultCryptographicMaterialsManager(defaultInput);
          if (data.containsKey("cmm") && data.get("cmm").equals("RequiredEncryptionContext")) {
            List<String> requiredKeys = new ArrayList<String>(2);
            requiredKeys.add("key1");
            requiredKeys.add("key2");
            CreateRequiredEncryptionContextCMMInput requiredCMMInput =
                CreateRequiredEncryptionContextCMMInput.builder()
                    .underlyingCMM(
                        materialProviders.CreateDefaultCryptographicMaterialsManager(defaultInput))
                    .requiredEncryptionContextKeys(requiredKeys)
                    .build();
            cmm = materialProviders.CreateRequiredEncryptionContextCMM(requiredCMMInput);
          }
          return cmm;
        };
    @SuppressWarnings("unchecked")
    final Map<String, Object> resultSpec = (Map<String, Object>) data.get("result");
    final ResultMatcher matcher = parseResultMatcher(jar, resultSpec);

    Map<String, String> ec = Collections.emptyMap();

    if (data.get("encryption-context") != null) {
      ec = (Map<String, String>) data.get("encryption-context");
    }

    String decryptionMethodSpec = (String) data.get("decryption-method");
    SignaturePolicy signaturePolicy = SignaturePolicy.AllowEncryptAllowDecrypt;
    if (decryptionMethodSpec != null) {
      if ("streaming-unsigned-only".equals(decryptionMethodSpec)) {
        signaturePolicy = SignaturePolicy.AllowEncryptForbidDecrypt;
      } else {
        throw new IllegalArgumentException(
            "Unsupported Decryption Method: " + decryptionMethodSpec);
      }
    }

    return new TestCase(
        testName, ciphertextURL, true, null, cmmSupplier, ec, matcher, signaturePolicy);
  }

  /** Parse Test to MasterKey for AWS SDK v1 */
  @SuppressWarnings("unchecked")
  private static <T> TestCase parseTest(
      String testName,
      Map<String, Object> data,
      Map<String, KeyEntry> keys,
      JarFile jar,
      KmsMasterKeyProvider kmsProv)
      throws IOException {
    final String ciphertextURL = (String) data.get("ciphertext");
    cacheData(jar, ciphertextURL);

    Supplier<MasterKeyProvider<?>> mkpSupplier =
        () -> {
          @SuppressWarnings("generic")
          final List<MasterKey<?>> mks = new ArrayList<>();

          for (Map<String, Object> mkEntry : (List<Map<String, Object>>) data.get("master-keys")) {
            final String type = (String) mkEntry.get("type");
            final String keyName = (String) mkEntry.get("key");
            final KeyEntry key = keys.get(keyName);

            if ("aws-kms".equals(type)) {
              mks.add(kmsProv.getMasterKey(key.keyId));
            } else if ("aws-kms-mrk-aware".equals(type)) {
              AwsKmsMrkAwareMasterKeyProvider provider =
                  AwsKmsMrkAwareMasterKeyProvider.builder().buildStrict(key.keyId);
              mks.add(provider.getMasterKey(key.keyId));
            } else if ("aws-kms-mrk-aware-discovery".equals(type)) {
              final String defaultMrkRegion = (String) mkEntry.get("default-mrk-region");
              final Map<String, Object> discoveryFilterSpec =
                  (Map<String, Object>) mkEntry.get("aws-kms-discovery-filter");
              final DiscoveryFilter discoveryFilter;
              if (discoveryFilterSpec != null) {
                discoveryFilter =
                    new DiscoveryFilter(
                        (String) discoveryFilterSpec.get("partition"),
                        (List<String>) discoveryFilterSpec.get("account-ids"));
              } else {
                discoveryFilter = null;
              }
              return AwsKmsMrkAwareMasterKeyProvider.builder()
                  .withDiscoveryMrkRegion(defaultMrkRegion)
                  .buildDiscovery(discoveryFilter);
            } else if ("raw".equals(type)) {
              final String provId = (String) mkEntry.get("provider-id");
              final String algorithm = (String) mkEntry.get("encryption-algorithm");
              if ("aes".equals(algorithm)) {
                mks.add(
                    JceMasterKey.getInstance(
                        (SecretKey) key.key, provId, key.keyId, "AES/GCM/NoPadding"));
              } else if ("rsa".equals(algorithm)) {
                String transformation = "RSA/ECB/";
                final String padding = (String) mkEntry.get("padding-algorithm");
                if ("pkcs1".equals(padding)) {
                  transformation += "PKCS1Padding";
                } else if ("oaep-mgf1".equals(padding)) {
                  final String hashName =
                      ((String) mkEntry.get("padding-hash"))
                          .replace("sha", "sha-")
                          .toUpperCase(Locale.ROOT);
                  transformation += "OAEPWith" + hashName + "AndMGF1Padding";
                } else {
                  throw new IllegalArgumentException("Unsupported padding:" + padding);
                }
                final PublicKey wrappingKey;
                final PrivateKey unwrappingKey;
                if (key.key instanceof PublicKey) {
                  wrappingKey = (PublicKey) key.key;
                  unwrappingKey = null;
                } else {
                  wrappingKey = null;
                  unwrappingKey = (PrivateKey) key.key;
                }
                mks.add(
                    JceMasterKey.getInstance(
                        wrappingKey, unwrappingKey, provId, key.keyId, transformation));
              } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
              }
            } else {
              throw new IllegalArgumentException("Unsupported Key Type: " + type);
            }
          }

          return MultipleProviderFactory.buildMultiProvider(mks);
        };

    @SuppressWarnings("unchecked")
    final Map<String, Object> resultSpec = (Map<String, Object>) data.get("result");
    final ResultMatcher matcher = parseResultMatcher(jar, resultSpec);

    String decryptionMethodSpec = (String) data.get("decryption-method");
    SignaturePolicy signaturePolicy = SignaturePolicy.AllowEncryptAllowDecrypt;
    if (decryptionMethodSpec != null) {
      if ("streaming-unsigned-only".equals(decryptionMethodSpec)) {
        signaturePolicy = SignaturePolicy.AllowEncryptForbidDecrypt;
      } else {
        throw new IllegalArgumentException(
            "Unsupported Decryption Method: " + decryptionMethodSpec);
      }
    }

    return new TestCase(
        testName,
        ciphertextURL,
        false,
        mkpSupplier,
        null,
        Collections.emptyMap(),
        matcher,
        signaturePolicy);
  }

  /** Parse Test to MasterKey for AWS SDK v2 */
  @SuppressWarnings("unchecked")
  private static TestCase parseTest(
      String testName,
      Map<String, Object> data,
      Map<String, KeyEntry> keys,
      JarFile jar,
      com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider kmsProv)
      throws IOException {
    final String ciphertextURL = (String) data.get("ciphertext");
    cacheData(jar, ciphertextURL);

    Supplier<MasterKeyProvider<?>> mkpSupplier =
        () -> {
          @SuppressWarnings("generic")
          final List<MasterKey<?>> mks = new ArrayList<>();

          for (Map<String, Object> mkEntry : (List<Map<String, Object>>) data.get("master-keys")) {
            final String type = (String) mkEntry.get("type");
            final String keyName = (String) mkEntry.get("key");
            final KeyEntry key = keys.get(keyName);

            if ("aws-kms".equals(type)) {
              mks.add(kmsProv.getMasterKey(key.keyId));
            } else if ("aws-kms-mrk-aware".equals(type)) {
              com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider provider =
                  com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider.builder()
                      .buildStrict(key.keyId);
              mks.add(provider.getMasterKey(key.keyId));
            } else if ("aws-kms-mrk-aware-discovery".equals(type)) {
              final String defaultMrkRegion = (String) mkEntry.get("default-mrk-region");
              final Map<String, Object> discoveryFilterSpec =
                  (Map<String, Object>) mkEntry.get("aws-kms-discovery-filter");
              final DiscoveryFilter discoveryFilter;
              if (discoveryFilterSpec != null) {
                discoveryFilter =
                    new DiscoveryFilter(
                        (String) discoveryFilterSpec.get("partition"),
                        (List<String>) discoveryFilterSpec.get("account-ids"));
              } else {
                discoveryFilter = null;
              }
              return com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider.builder()
                  .discoveryMrkRegion(Region.of(defaultMrkRegion))
                  .buildDiscovery(discoveryFilter);
            } else if ("raw".equals(type)) {
              final String provId = (String) mkEntry.get("provider-id");
              final String algorithm = (String) mkEntry.get("encryption-algorithm");
              if ("aes".equals(algorithm)) {
                mks.add(
                    JceMasterKey.getInstance(
                        (SecretKey) key.key, provId, key.keyId, "AES/GCM/NoPadding"));
              } else if ("rsa".equals(algorithm)) {
                String transformation = "RSA/ECB/";
                final String padding = (String) mkEntry.get("padding-algorithm");
                if ("pkcs1".equals(padding)) {
                  transformation += "PKCS1Padding";
                } else if ("oaep-mgf1".equals(padding)) {
                  final String hashName =
                      ((String) mkEntry.get("padding-hash"))
                          .replace("sha", "sha-")
                          .toUpperCase(Locale.ROOT);
                  transformation += "OAEPWith" + hashName + "AndMGF1Padding";
                } else {
                  throw new IllegalArgumentException("Unsupported padding:" + padding);
                }
                final PublicKey wrappingKey;
                final PrivateKey unwrappingKey;
                if (key.key instanceof PublicKey) {
                  wrappingKey = (PublicKey) key.key;
                  unwrappingKey = null;
                } else {
                  wrappingKey = null;
                  unwrappingKey = (PrivateKey) key.key;
                }
                mks.add(
                    JceMasterKey.getInstance(
                        wrappingKey, unwrappingKey, provId, key.keyId, transformation));
              } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
              }
            } else {
              throw new IllegalArgumentException("Unsupported Key Type: " + type);
            }
          }

          return MultipleProviderFactory.buildMultiProvider(mks);
        };

    @SuppressWarnings("unchecked")
    final Map<String, Object> resultSpec = (Map<String, Object>) data.get("result");
    final ResultMatcher matcher = parseResultMatcher(jar, resultSpec);

    String decryptionMethodSpec = (String) data.get("decryption-method");
    SignaturePolicy signaturePolicy = SignaturePolicy.AllowEncryptAllowDecrypt;
    if (decryptionMethodSpec != null) {
      if ("streaming-unsigned-only".equals(decryptionMethodSpec)) {
        signaturePolicy = SignaturePolicy.AllowEncryptForbidDecrypt;
      } else {
        throw new IllegalArgumentException(
            "Unsupported Decryption Method: " + decryptionMethodSpec);
      }
    }

    return new TestCase(
        testName,
        ciphertextURL,
        false,
        mkpSupplier,
        null,
        Collections.emptyMap(),
        matcher,
        signaturePolicy);
  }

  private static ResultMatcher parseResultMatcher(
      final JarFile jar, final Map<String, Object> result) throws IOException {
    if (result.size() != 1) {
      throw new IllegalArgumentException("Unsupported result specification: " + result);
    }
    Map.Entry<String, Object> pair = result.entrySet().iterator().next();
    if (pair.getKey().equals("output")) {
      Map<String, String> outputSpec = (Map<String, String>) pair.getValue();
      String plaintextUrl = outputSpec.get("plaintext");
      cacheData(jar, plaintextUrl);
      return new OutputResultMatcher(plaintextUrl);
    } else if (pair.getKey().equals("error")) {
      Map<String, String> errorSpec = (Map<String, String>) pair.getValue();
      String errorDescription = errorSpec.get("error-description");
      return new ErrorResultMatcher(errorDescription);
    } else {
      throw new IllegalArgumentException("Unsupported result specification: " + result);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, KeyEntry> parseKeyManifest(final Map<String, Object> keysManifest)
      throws GeneralSecurityException {
    // check our type
    final Map<String, Object> metaData = (Map<String, Object>) keysManifest.get("manifest");
    if (!"keys".equals(metaData.get("type"))) {
      throw new IllegalArgumentException("Invalid manifest type: " + metaData.get("type"));
    }
    if (!Integer.valueOf(3).equals(metaData.get("version"))) {
      throw new IllegalArgumentException("Invalid manifest version: " + metaData.get("version"));
    }

    final Map<String, KeyEntry> result = new HashMap<>();

    Map<String, Object> keys = (Map<String, Object>) keysManifest.get("keys");
    for (Map.Entry<String, Object> entry : keys.entrySet()) {
      final String name = entry.getKey();
      final Map<String, Object> data = (Map<String, Object>) entry.getValue();

      final String keyType = (String) data.get("type");
      final String encoding = (String) data.get("encoding");
      final String keyId = (String) data.get("key-id");
      final String material = (String) data.get("material"); // May be null
      final String algorithm = (String) data.get("algorithm"); // May be null

      final KeyEntry keyEntry;

      final KeyFactory kf;
      switch (keyType) {
        case "symmetric":
          if (!"base64".equals(encoding)) {
            throw new IllegalArgumentException(
                format("Key %s is symmetric but has encoding %s", keyId, encoding));
          }
          keyEntry =
              new KeyEntry(
                  name,
                  keyId,
                  keyType,
                  new SecretKeySpec(Base64.decode(material), algorithm.toUpperCase(Locale.ROOT)));
          break;
        case "private":
          kf = KeyFactory.getInstance(algorithm);
          if (!"pem".equals(encoding)) {
            throw new IllegalArgumentException(
                format("Key %s is private but has encoding %s", keyId, encoding));
          }
          byte[] pkcs8Key = parsePem(material);
          keyEntry =
              new KeyEntry(
                  name, keyId, keyType, kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Key)));
          break;
        case "public":
          kf = KeyFactory.getInstance(algorithm);
          if (!"pem".equals(encoding)) {
            throw new IllegalArgumentException(
                format("Key %s is private but has encoding %s", keyId, encoding));
          }
          byte[] x509Key = parsePem(material);
          keyEntry =
              new KeyEntry(
                  name, keyId, keyType, kf.generatePublic(new X509EncodedKeySpec(x509Key)));
          break;
        case "aws-kms":
          keyEntry = new KeyEntry(name, keyId, keyType, null);
          break;
        default:
          throw new IllegalArgumentException("Unsupported key type: " + keyType);
      }

      result.put(name, keyEntry);
    }

    return result;
  }

  private static byte[] parsePem(String pem) {
    final String stripped = pem.replaceAll("-+[A-Z ]+-+", "");
    return Base64.decode(stripped);
  }

  private static class KeyEntry {
    final String name;
    final String keyId;
    final String type;
    final Key key;

    private KeyEntry(String name, String keyId, String type, Key key) {
      this.name = name;
      this.keyId = keyId;
      this.type = type;
      this.key = key;
    }
  }

  private static class TestCase {
    private final String name;
    private final String ciphertextPath;
    private final ResultMatcher matcher;
    private final boolean isKeyring;
    private final Supplier<MasterKeyProvider<?>> mkpSupplier;
    private final Supplier<ICryptographicMaterialsManager> cmmSupplier;
    private final Map<String, String> encryptionContext;
    private final SignaturePolicy signaturePolicy;

    private TestCase(
        String name,
        String ciphertextPath,
        boolean isKeyring,
        Supplier<MasterKeyProvider<?>> mkpSupplier,
        Supplier<ICryptographicMaterialsManager> cmmSupplier,
        Map<String, String> encryptionContext,
        ResultMatcher matcher,
        SignaturePolicy signaturePolicy) {
      this.name = name;
      this.ciphertextPath = ciphertextPath;
      this.matcher = matcher;
      this.isKeyring = isKeyring;
      this.mkpSupplier = mkpSupplier;
      this.cmmSupplier = cmmSupplier;
      this.encryptionContext = encryptionContext;
      this.signaturePolicy = signaturePolicy;
    }
  }

  private interface ResultMatcher {
    void Match(Callable<byte[]> decryptor) throws Exception;
  }

  private static class OutputResultMatcher implements ResultMatcher {

    private final String plaintextPath;

    private OutputResultMatcher(String plaintextPath) {
      this.plaintextPath = plaintextPath;
    }

    @Override
    public void Match(Callable<byte[]> decryptor) throws Exception {
      final byte[] plaintext = decryptor.call();
      final byte[] expectedPlaintext = cachedData.get(plaintextPath);
      Assert.assertArrayEquals(expectedPlaintext, plaintext);
    }
  }

  private static class ErrorResultMatcher implements ResultMatcher {

    private final String errorDescription;

    private ErrorResultMatcher(String errorDescription) {
      this.errorDescription = errorDescription;
    }

    @Override
    public void Match(Callable<byte[]> decryptor) {
      Assert.assertThrows(
          "Decryption expected to fail (" + errorDescription + ") but succeeded",
          Exception.class,
          decryptor::call);
    }
  }
}
