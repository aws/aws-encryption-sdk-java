// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static java.lang.String.format;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import software.amazon.awssdk.utils.ImmutableMap;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviderstestvectorkeys.KeyVectors;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.GetKeyDescriptionInput;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.GetKeyDescriptionOutput;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.KeyVectorsConfig;
import software.amazon.cryptography.materialproviderstestvectorkeys.model.TestVectorKeyringInput;

@RunWith(Parameterized.class)
public class TestVectorGenerator {

  private static final String encryptManifestList =
      "https://raw.githubusercontent.com/awslabs/aws-crypto-tools-test-vector-framework/master/features/CANONICAL-GENERATED-MANIFESTS/0003-awses-message-encryption.v2.json";
  // We save the files in memory to avoid repeatedly retrieving them. This won't work if the
  // plaintexts are too
  // large or numerous
  private static final Map<String, byte[]> cachedData = new HashMap<>();
  private static final ObjectMapper mapper = new ObjectMapper();
  private static EncryptionInterface encryption;
  private static boolean isMasterKey;
  private final String testName;
  private final TestCase testCase;

  // Temp Test Vectors Directory
  private static String tempTestVectorPath;
  // Zip File Path
  private static String zipFilePath;

  public TestVectorGenerator(final String testName, TestCase testCase) {
    this.testName = testName;
    this.testCase = testCase;
  }

  // Zip Temp Folder and delete temp files
  @AfterClass
  public static void zip() throws IOException {
    Path zipFile = Files.createFile(Paths.get(zipFilePath));

    Path sourceDirPath = Paths.get(tempTestVectorPath);
    try (ZipOutputStream zipOutputStream = new ZipOutputStream(Files.newOutputStream(zipFile));
        Stream<Path> paths = Files.walk(sourceDirPath)) {
      paths
          .filter(path -> !Files.isDirectory(path))
          .forEach(
              path -> {
                ZipEntry zipEntry = new ZipEntry(sourceDirPath.relativize(path).toString());
                try {
                  zipOutputStream.putNextEntry(zipEntry);
                  Files.copy(path, zipOutputStream);
                  zipOutputStream.closeEntry();
                } catch (IOException e) {
                  throw new UncheckedIOException("Unable to Zip File", e);
                }
              });
    }
    FileUtils.deleteQuietly(sourceDirPath.toFile());

    // Teardown
    cachedData.clear();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void encrypt() throws Exception {
    CryptoAlgorithm cryptoAlgorithm = getCryptoAlgorithm(testCase.algorithmId);
    CommitmentPolicy commitmentPolicy =
        cryptoAlgorithm.isCommitting()
            ? CommitmentPolicy.RequireEncryptRequireDecrypt
            : CommitmentPolicy.ForbidEncryptAllowDecrypt;

    AwsCrypto crypto =
        AwsCrypto.builder()
            .withCommitmentPolicy(commitmentPolicy)
            .withEncryptionAlgorithm(cryptoAlgorithm)
            .withEncryptionFrameSize(testCase.frameSize)
            .build();

    Callable<byte[]> ciphertext;
    if (isMasterKey) {
      ciphertext =
          () ->
              crypto
                  .encryptData(
                      testCase.masterKey,
                      cachedData.get(testCase.plaintext),
                      testCase.encryptionContext)
                  .getResult();
    } else {
      ciphertext =
          () ->
              crypto
                  .encryptData(
                      testCase.keyring,
                      cachedData.get(testCase.plaintext),
                      testCase.encryptionContext)
                  .getResult();
    }
    Files.write(Paths.get(tempTestVectorPath + "ciphertexts/" + testName), ciphertext.call());
  }

  private static CryptoAlgorithm getCryptoAlgorithm(String algorithmId) {
    Integer algId = Integer.parseInt(algorithmId, 16);
    for (CryptoAlgorithm cryptoAlgorithm : CryptoAlgorithm.values()) {
      if (cryptoAlgorithm.getValue() == algId) {
        return cryptoAlgorithm;
      }
    }
    throw new IllegalArgumentException("Invalid AlgorithmId: " + algorithmId);
  }

  @Parameterized.Parameters(name = "Compatibility Test: {0} - {1}")
  @SuppressWarnings("unchecked")
  public static Collection<Object[]> data() throws Exception {
    final String interfaceOption = System.getProperty("masterkey");

    if (interfaceOption != null && interfaceOption.equals("true")) {
      isMasterKey = true;
      encryption = EncryptionInterface.EncryptWithMasterKey;
    } else {
      encryption = EncryptionInterface.EncryptWithKeyring;
    }

    final String encryptKeyManifest = System.getProperty("keysManifest");
    if (encryptKeyManifest == null) {
      return Collections.emptyList();
    }

    zipFilePath = System.getProperty("zipFilePath");
    if (zipFilePath == null) {
      return Collections.emptyList();
    }

    tempTestVectorPath = Files.createTempDirectory("java", new FileAttribute[0]).toString() + "/";
    createDirectories(tempTestVectorPath + "ciphertexts/");
    createDirectories(tempTestVectorPath + "plaintexts/");

    File decryptManifest = new File(tempTestVectorPath + "manifest.json");
    File keyManifest = new File(tempTestVectorPath + "keys.json");

    final Map<String, Object> manifest = mapper.readValue(new URL(encryptManifestList), Map.class);
    mapper
        .writerWithDefaultPrettyPrinter()
        .writeValue(decryptManifest, createDecryptManifest(manifest));

    try (InputStream in = new FileInputStream(encryptKeyManifest)) {
      Files.copy(in, keyManifest.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    final Map<String, Object> keysManifest =
        mapper.readValue(new File(encryptKeyManifest), Map.class);

    cachePlaintext((Map<String, Integer>) manifest.get("plaintexts"));

    MaterialProvidersConfig config = MaterialProvidersConfig.builder().build();
    MaterialProviders materialProviders =
        MaterialProviders.builder().MaterialProvidersConfig(config).build();
    KeyVectors keyVectors =
        KeyVectors.builder()
            .KeyVectorsConfig(
                KeyVectorsConfig.builder().keyManifiestPath(keyManifest.toString()).build())
            .build();

    final Map<String, KeyEntry> keys = parseKeyManifest(keysManifest);
    final KmsMasterKeyProvider kmsProv =
        KmsMasterKeyProvider.builder()
            .withCredentials(new DefaultAWSCredentialsProviderChain())
            .buildDiscovery();

    return ((Map<String, Map<String, Object>>) manifest.get("tests"))
        .entrySet().stream()
            .map(
                entry -> {
                  String testName = entry.getKey();
                  TestCase testCase =
                      encryption.parseTest(entry, keys, kmsProv, materialProviders, keyVectors);
                  return new Object[] {testName, testCase};
                })
            .collect(Collectors.toList());
  }

  private static void createDirectories(String path) {
    File directory = new File(path);
    directory.mkdirs();
  }

  private enum EncryptionInterface {
    EncryptWithMasterKey {
      @Override
      public TestCase parseTest(
          Map.Entry<String, Map<String, Object>> testEntry,
          Map<String, KeyEntry> keys,
          KmsMasterKeyProvider kmsProv,
          MaterialProviders materialProviders,
          KeyVectors keyVectors) {
        return parseTestWithMasterkeys(testEntry, keys, kmsProv);
      }
    },
    EncryptWithKeyring {
      @Override
      public TestCase parseTest(
          Map.Entry<String, Map<String, Object>> testEntry,
          Map<String, KeyEntry> keys,
          KmsMasterKeyProvider kmsProv,
          MaterialProviders materialProviders,
          KeyVectors keyVectors) {
        return parseTestWithKeyrings(testEntry, materialProviders, keyVectors);
      }
    };

    public abstract TestCase parseTest(
        Map.Entry<String, Map<String, Object>> testEntry,
        Map<String, KeyEntry> keys,
        KmsMasterKeyProvider kmsProv,
        MaterialProviders materialProviders,
        KeyVectors keyVectors);
  }

  private static void cachePlaintext(Map<String, Integer> plaintexts) {
    Random rd = new Random();
    plaintexts.forEach(
        (key, value) -> {
          byte[] plaintext = new byte[value];
          rd.nextBytes(plaintext);
          try {
            Files.write(new File(tempTestVectorPath + "plaintexts/" + key).toPath(), plaintext);
            cachedData.put(key, plaintext);
          } catch (IOException e) {
            throw new UncheckedIOException(e);
          }
        });
  }

  private static Map<String, Object> createDecryptManifest(Map<String, Object> encryptManifest) {
    Map<String, Object> decryptManifest = new LinkedHashMap<>();

    decryptManifest.put("manifest", ImmutableMap.of("type", "awses-decrypt", "version", 2));

    decryptManifest.put(
        "client", ImmutableMap.of("name", "aws/aws-encryption-sdk-java", "version", "2.2.0"));

    decryptManifest.put("keys", "file://keys.json");

    Map<String, Map<String, Object>> testScenarios =
        ((LinkedHashMap<String, Map<String, Object>>) encryptManifest.get("tests"))
            .entrySet().stream()
                .collect(
                    Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> {
                          Map<String, Object> scenario = entry.getValue();
                          return new LinkedHashMap<String, Object>() {
                            {
                              put("ciphertext", "file://ciphertexts/" + entry.getKey());
                              put("master-keys", scenario.get("master-keys"));
                              put(
                                  "result",
                                  Collections.singletonMap(
                                      "output",
                                      Collections.singletonMap(
                                          "plaintext",
                                          "file://plaintexts/" + scenario.get("plaintext"))));
                            }
                          };
                        }));

    decryptManifest.put("tests", testScenarios);
    return decryptManifest;
  }

  private static TestCase parseTestWithMasterkeys(
      Map.Entry<String, Map<String, Object>> testEntry,
      Map<String, KeyEntry> keys,
      KmsMasterKeyProvider kmsProv) {

    String testName = testEntry.getKey();
    Map<String, Object> data = testEntry.getValue();

    String plaintext = (String) data.get("plaintext");
    String algorithmId = (String) data.get("algorithm");
    int frameSize = (int) data.get("frame-size");
    Map<String, String> encryptionContext = (Map<String, String>) data.get("encryption-context");

    final List<MasterKey<?>> mks = new ArrayList<>();

    for (Map<String, String> mkEntry : (List<Map<String, String>>) data.get("master-keys")) {
      if (mkEntry.get("key").equals("rsa-4096-private")) {
        mkEntry.replace("key", "rsa-4096-public");
      }

      final String type = mkEntry.get("type");
      final String keyName = mkEntry.get("key");
      final KeyEntry key = keys.get(keyName);

      if ("aws-kms".equals(type)) {
        mks.add(kmsProv.getMasterKey(key.keyId));
      } else if ("raw".equals(type)) {
        final String provId = mkEntry.get("provider-id");
        final String algorithm = mkEntry.get("encryption-algorithm");
        if ("aes".equals(algorithm)) {
          mks.add(
              JceMasterKey.getInstance(
                  (SecretKey) key.key, provId, key.keyId, "AES/GCM/NoPadding"));
        } else if ("rsa".equals(algorithm)) {
          String transformation = "RSA/ECB/";
          final String padding = mkEntry.get("padding-algorithm");
          if ("pkcs1".equals(padding)) {
            transformation += "PKCS1Padding";
          } else if ("oaep-mgf1".equals(padding)) {
            final String hashName =
                mkEntry.get("padding-hash").replace("sha", "sha-").toUpperCase();
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

    MasterKeyProvider<?> multiProvider = MultipleProviderFactory.buildMultiProvider(mks);

    return new TestCase(
        testName, null, multiProvider, plaintext, algorithmId, frameSize, encryptionContext);
  }

  private static TestCase parseTestWithKeyrings(
      Map.Entry<String, Map<String, Object>> testEntry,
      MaterialProviders materialProviders,
      KeyVectors keyVectors) {
    String testName = testEntry.getKey();
    Map<String, Object> data = testEntry.getValue();

    String plaintext = (String) data.get("plaintext");
    String algorithmId = (String) data.get("algorithm");
    int frameSize = (int) data.get("frame-size");
    Map<String, String> encryptionContext = (Map<String, String>) data.get("encryption-context");

    List<IKeyring> keyrings = new ArrayList<>();

    ((List<Map<String, String>>) data.get("master-keys"))
        .forEach(
            mkEntry -> {
              if (mkEntry.get("type").equals("raw")
                  && mkEntry.get("encryption-algorithm").equals("rsa")) {
                if (mkEntry.get("key").equals("rsa-4096-private")) {
                  mkEntry.replace("key", "rsa-4096-public");
                }
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
            });

    IKeyring primary = keyrings.remove(0);
    IKeyring multiKeyring =
        materialProviders.CreateMultiKeyring(
            CreateMultiKeyringInput.builder().generator(primary).childKeyrings(keyrings).build());

    return new TestCase(
        testName, multiKeyring, null, plaintext, algorithmId, frameSize, encryptionContext);
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
    private final IKeyring keyring;
    private final MasterKeyProvider<?> masterKey;
    private final String plaintext;
    private final String algorithmId;
    private final int frameSize;
    private final Map<String, String> encryptionContext;

    public TestCase(
        String name,
        IKeyring keyring,
        MasterKeyProvider<?> multiProvider,
        String plaintext,
        String algorithmId,
        int frameSize,
        Map<String, String> encryptionContext) {
      this.name = name;
      this.keyring = keyring;
      this.masterKey = multiProvider;
      this.plaintext = plaintext;
      this.algorithmId = algorithmId;
      this.frameSize = frameSize;
      this.encryptionContext = encryptionContext;
    }
  }
}
