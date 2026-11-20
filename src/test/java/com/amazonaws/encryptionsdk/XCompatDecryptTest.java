// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static org.junit.Assert.assertArrayEquals;

import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class XCompatDecryptTest {
  private static final String STATIC_XCOMPAT_NAME = "static-aws-xcompat";
  private static final String AES_GCM = "AES/GCM/NoPadding";
  private static final byte XCOMPAT_MESSAGE_VERSION = 1;

  private String plaintextFileName;
  private String ciphertextFileName;
  private MasterKeyProvider masterKeyProvider;

  public XCompatDecryptTest(
      String plaintextFileName, String ciphertextFileName, MasterKeyProvider masterKeyProvider)
      throws Exception {
    this.plaintextFileName = plaintextFileName;
    this.ciphertextFileName = ciphertextFileName;
    this.masterKeyProvider = masterKeyProvider;
  }

  @Parameters(name = "{index}: testDecryptFromFile({0}, {1}, {2})")
  public static Collection<Object[]> data() throws Exception {
    String baseDirName;
    baseDirName = System.getProperty("staticCompatibilityResourcesDir");
    if (baseDirName == null) {
      baseDirName =
          XCompatDecryptTest.class.getProtectionDomain().getCodeSource().getLocation().getPath()
              + "aws_encryption_sdk_resources";
    }

    List<Object[]> testCases_ = new ArrayList<Object[]>();

    String ciphertextManifestName =
        StringUtils.join(
            new String[] {baseDirName, "manifests", "ciphertext.manifest"}, File.separator);
    File ciphertextManifestFile = new File(ciphertextManifestName);

    if (!ciphertextManifestFile.exists()) {
      return Collections.emptySet();
    }

    ObjectMapper ciphertextManifestMapper = new ObjectMapper();
    Map<String, Object> ciphertextManifest =
        ciphertextManifestMapper.readValue(
            ciphertextManifestFile, new TypeReference<Map<String, Object>>() {});

    HashMap<String, HashMap<String, byte[]>> staticKeyMap =
        new HashMap<String, HashMap<String, byte[]>>();

    Map<String, Object> testKeys = (Map<String, Object>) ciphertextManifest.get("test_keys");

    for (Map.Entry<String, Object> keyType : testKeys.entrySet()) {
      Map<String, Object> keys = (Map<String, Object>) keyType.getValue();
      HashMap<String, byte[]> thisKeyType = new HashMap<String, byte[]>();
      for (Map.Entry<String, Object> key : keys.entrySet()) {
        Map<String, Object> thisKey = (Map<String, Object>) key.getValue();
        String keyRaw =
            new String(
                StringUtils.join(
                        (List<String>) thisKey.get("key"),
                        (String) thisKey.getOrDefault("line_separator", ""))
                    .getBytes(),
                StandardCharsets.UTF_8);
        byte[] keyBytes;
        switch ((String) thisKey.get("encoding")) {
          case "base64":
            keyBytes = Utils.decodeBase64String(keyRaw);
            break;
          case "pem":
            PemReader pemReader = new PemReader(new StringReader(keyRaw));
            keyBytes = pemReader.readPemObject().getContent();
            break;
          case "raw":
          default:
            keyBytes = keyRaw.getBytes();
        }
        thisKeyType.put((String) key.getKey(), keyBytes);
      }
      staticKeyMap.put((String) keyType.getKey(), thisKeyType);
    }

    final KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

    List<Map<String, Object>> testCases =
        (List<Map<String, Object>>) ciphertextManifest.get("test_cases");
    for (Map<String, Object> testCase : testCases) {
      Map<String, String> plaintext = (Map<String, String>) testCase.get("plaintext");
      Map<String, String> ciphertext = (Map<String, String>) testCase.get("ciphertext");

      short algId = (short) Integer.parseInt((String) testCase.get("algorithm"), 16);
      CryptoAlgorithm encryptionAlgorithm =
          CryptoAlgorithm.deserialize(XCOMPAT_MESSAGE_VERSION, algId);

      List<Map<String, Object>> masterKeys =
          (List<Map<String, Object>>) testCase.get("master_keys");
      List<JceMasterKey> allMasterKeys = new ArrayList<JceMasterKey>();
      for (Map<String, Object> aMasterKey : masterKeys) {
        String providerId = (String) aMasterKey.get("provider_id");
        if (providerId.equals(STATIC_XCOMPAT_NAME) && (boolean) aMasterKey.get("decryptable")) {
          String paddingAlgorithm = (String) aMasterKey.getOrDefault("padding_algorithm", "");
          String paddingHash = (String) aMasterKey.getOrDefault("padding_hash", "");
          Integer keyBits =
              (Integer)
                  aMasterKey.getOrDefault("key_bits", encryptionAlgorithm.getDataKeyLength() * 8);
          String keyId =
              (String) aMasterKey.get("encryption_algorithm")
                  + "."
                  + keyBits.toString()
                  + "."
                  + paddingAlgorithm
                  + "."
                  + paddingHash;
          String encAlg = (String) aMasterKey.get("encryption_algorithm");
          switch (encAlg.toUpperCase(Locale.ROOT)) {
            case "RSA":
              String cipherBase = "RSA/ECB/";
              String cipherName;
              switch (paddingAlgorithm) {
                case "OAEP-MGF1":
                  cipherName = cipherBase + "OAEPWith" + paddingHash + "AndMGF1Padding";
                  break;
                case "PKCS1":
                  cipherName = cipherBase + paddingAlgorithm + "Padding";
                  break;
                default:
                  throw new IllegalArgumentException(
                      "Unknown padding algorithm: " + paddingAlgorithm);
              }
              PrivateKey privKey =
                  rsaKeyFactory.generatePrivate(
                      new PKCS8EncodedKeySpec(staticKeyMap.get("RSA").get(keyBits.toString())));
              allMasterKeys.add(
                  JceMasterKey.getInstance(null, privKey, STATIC_XCOMPAT_NAME, keyId, cipherName));
              break;
            case "AES":
              SecretKeySpec spec =
                  new SecretKeySpec(
                      staticKeyMap.get("AES").get(keyBits.toString()),
                      0,
                      encryptionAlgorithm.getDataKeyLength(),
                      encryptionAlgorithm.getDataKeyAlgo());
              allMasterKeys.add(
                  JceMasterKey.getInstance(spec, STATIC_XCOMPAT_NAME, keyId, AES_GCM));
              break;
            default:
              throw new IllegalArgumentException(
                  "Unknown encryption algorithm: " + encAlg.toUpperCase(Locale.ROOT));
          }
        }
      }

      if (allMasterKeys.size() > 0) {
        final MasterKeyProvider<?> provider =
            MultipleProviderFactory.buildMultiProvider(allMasterKeys);
        testCases_.add(
            new Object[] {
              baseDirName + File.separator + plaintext.get("filename"),
              baseDirName + File.separator + ciphertext.get("filename"),
              provider
            });
      }
    }
    return testCases_;
  }

  @Test
  public void testDecryptFromFile() throws Exception {
    AwsCrypto crypto = AwsCrypto.standard();
    byte ciphertextBytes[] = Files.readAllBytes(Paths.get(ciphertextFileName));
    byte plaintextBytes[] = Files.readAllBytes(Paths.get(plaintextFileName));
    final CryptoResult decryptResult = crypto.decryptData(masterKeyProvider, ciphertextBytes);
    assertArrayEquals(plaintextBytes, (byte[]) decryptResult.getResult());
  }
}
