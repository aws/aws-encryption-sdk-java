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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import software.amazon.awssdk.regions.Region;

@RunWith(Parameterized.class)
public class TestVectorRunner {

  private static final int MANIFEST_VERSION = 2;

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
    Callable<byte[]> decryptor =
        () ->
            decryptionMethod.decryptMessage(
                crypto, testCase.mkpSupplier.get(), cachedData.get(testCase.ciphertextPath));
    testCase.matcher.Match(decryptor);
  }

  @Parameterized.Parameters(name = "Compatibility Test: {0} - {2}")
  @SuppressWarnings("unchecked")
  public static Collection<Object[]> data() throws Exception {
    final String zipPath = System.getProperty("testVectorZip");
    if (zipPath == null) {
      return Collections.emptyList();
    }

    final JarURLConnection jarConnection =
        (JarURLConnection) new URL("jar:" + zipPath + "!/").openConnection();

    try (JarFile jar = jarConnection.getJarFile()) {
      final Map<String, Object> manifest = readJsonMapFromJar(jar, "manifest.json");

      final Map<String, Object> metaData = (Map<String, Object>) manifest.get("manifest");

      // We only support "awses-decrypt" type manifests right now
      if (!"awses-decrypt".equals(metaData.get("type"))) {
        throw new IllegalArgumentException("Unsupported manifest type: " + metaData.get("type"));
      }

      if (!Integer.valueOf(MANIFEST_VERSION).equals(metaData.get("version"))) {
        throw new IllegalArgumentException(
            "Unsupported manifest version: " + metaData.get("version"));
      }

      final Map<String, KeyEntry> keys =
          parseKeyManifest(readJsonMapFromJar(jar, (String) manifest.get("keys")));

      final KmsMasterKeyProvider kmsProvV1 =
          KmsMasterKeyProvider.builder()
              .withCredentials(new DefaultAWSCredentialsProviderChain())
              .buildDiscovery();

      final com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider kmsProvV2 =
          com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider.builder().buildDiscovery();

      List<Object[]> testCases = new ArrayList<>();
      for (Map.Entry<String, Map<String, Object>> testEntry :
          ((Map<String, Map<String, Object>>) manifest.get("tests")).entrySet()) {
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
                      ((String) mkEntry.get("padding-hash")).replace("sha", "sha-").toUpperCase();
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

    return new TestCase(testName, ciphertextURL, mkpSupplier, matcher, signaturePolicy);
  }

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
                      ((String) mkEntry.get("padding-hash")).replace("sha", "sha-").toUpperCase();
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

    return new TestCase(testName, ciphertextURL, mkpSupplier, matcher, signaturePolicy);
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
                  new SecretKeySpec(Base64.decode(material), algorithm.toUpperCase()));
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
    private final Supplier<MasterKeyProvider<?>> mkpSupplier;
    private final SignaturePolicy signaturePolicy;

    private TestCase(
        String name,
        String ciphertextPath,
        Supplier<MasterKeyProvider<?>> mkpSupplier,
        ResultMatcher matcher,
        SignaturePolicy signaturePolicy) {
      this.name = name;
      this.ciphertextPath = ciphertextPath;
      this.matcher = matcher;
      this.mkpSupplier = mkpSupplier;
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
