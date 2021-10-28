package com.amazonaws.encryptionsdk.caching;

import static com.amazonaws.encryptionsdk.CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256;
import static com.amazonaws.encryptionsdk.CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.KeyBlob;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class CacheIdentifierTests {

  static String partitionName = "c15b9079-6d0e-42b6-8784-5e804b025692";
  static Map<String, String> contextEmpty = Collections.emptyMap();
  static Map<String, String> contextFull;
  static CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;

  static {
    contextFull = new HashMap<>();
    contextFull.put("this", "is");
    contextFull.put("a", "non-empty");
    contextFull.put("encryption", "context");
  }

  static List<KeyBlob> keyBlobs =
      Arrays.asList(
          new KeyBlob(
              "this is a provider ID",
              "this is some key info".getBytes(UTF_8),
              "super secret key, now with encryption!".getBytes(UTF_8)),
          new KeyBlob(
              "another provider ID!",
              "this is some different key info".getBytes(UTF_8),
              "better super secret key, now with encryption!".getBytes(UTF_8)));

  @Test
  public void pythonTestVecs() throws Exception {
    assertEncryptId(
        partitionName,
        null,
        contextEmpty,
        "rkrFAso1YyPbOJbmwVMjrPw+wwLJT7xusn8tA8zMe9e3+OqbtfDueB7bvoKLU3fsmdUvZ6eMt7mBp1ThMMB25Q==");
    assertEncryptId(
        partitionName,
        ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        contextEmpty,
        "3icBIkLK4V3fVwbm3zSxUdUQV6ZvZYUOLl8buN36g6gDMqAkghcGryxX7QiVABkW1JhB6GRp5z+bzbiuciBcKQ==");
    assertEncryptId(
        partitionName,
        null,
        contextFull,
        "IHiUHYOUVUEFTc3BcZPJDlsWct2Qy1A7JdfQl9sQoV/ILIbRpoz9q7RtGd/MlibaGl5ihE66cN8ygM8A5rtYbg==");
    assertEncryptId(
        partitionName,
        ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        contextFull,
        "mRNK7qhTb/kJiiyGPgAevp0gwFRcET4KeeNYwZHhoEDvSUzQiDgl8Of+YRDaVzKxAqpNBgcAuFXde9JlaRRsmw==");

    assertDecryptId(
        partitionName,
        ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256,
        Collections.singletonList(keyBlobs.get(0)),
        contextEmpty,
        "n0zVzk9QIVxhz6ET+aJIKKOJNxtpGtSe1yAbu7WU5l272Iw/jmhlER4psDHJs9Mr8KYiIvLGSXzggNDCc23+9w==");

    assertDecryptId(
        partitionName,
        ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        keyBlobs,
        contextFull,
        "+rtwUe38CGnczGmYu12iqGWHIyDyZ44EvYQ4S6ACmsgS8VaEpiw0RTGpDk6Z/7YYN/jVHOAcNKDyCNP8EmstFg==");
  }

  void assertDecryptId(
      String partitionName,
      CryptoAlgorithm algo,
      List<KeyBlob> blobs,
      Map<String, String> context,
      String expect)
      throws Exception {
    DecryptionMaterialsRequest request =
        DecryptionMaterialsRequest.newBuilder()
            .setAlgorithm(algo)
            .setEncryptionContext(context)
            .setEncryptedDataKeys(blobs)
            .build();

    byte[] id = getCacheIdentifier(getCMM(partitionName), request);

    assertEquals(expect, Utils.encodeBase64String(id));
  }

  void assertEncryptId(
      String partitionName, CryptoAlgorithm algo, Map<String, String> context, String expect)
      throws Exception {
    EncryptionMaterialsRequest request =
        EncryptionMaterialsRequest.newBuilder()
            .setContext(context)
            .setRequestedAlgorithm(algo)
            .build();

    byte[] id = getCacheIdentifier(getCMM(partitionName), request);

    assertEquals(expect, Utils.encodeBase64String(id));
  }

  @Test
  public void encryptDigestTestVector() throws Exception {
    HashMap<String, String> contextMap = new HashMap<>();

    contextMap.put("\0\0TEST", "\0\0test");
    // Note! This key is actually U+10000, but java treats it as a UTF-16 surrogate pair.
    // UTF-8 encoding should be 0xF0 0x90 0x80 0x80
    contextMap.put("\uD800\uDC00", "UTF-16 surrogate");
    contextMap.put("\uABCD", "\\uABCD");

    byte[] id =
        getCacheIdentifier(
            getCMM("partition ID"),
            EncryptionMaterialsRequest.newBuilder()
                .setContext(contextMap)
                .setRequestedAlgorithm(null)
                .build());

    assertEquals(
        "683328d033fc60a20e3d3936190b33d91aad0143163226af9530e7d1b3de0e96"
            + "39c00a2885f9cea09cf9a273bef316a39616475b50adc2441b69f67e1a25145f",
        new String(Hex.encode(id)));

    id =
        getCacheIdentifier(
            getCMM("partition ID"),
            EncryptionMaterialsRequest.newBuilder()
                .setContext(contextMap)
                .setRequestedAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256)
                .build());

    assertEquals(
        "3dc70ff1d4621059b97179563ab6592dff4319bfaf8ed1a819c96d33d3194d5c"
            + "354a361e879d0356e4d9e868170ebc9e934fa5eaf6e6d11de4ee801645723fa9",
        new String(Hex.encode(id)));
  }

  @Test
  public void decryptDigestTestVector() throws Exception {
    HashMap<String, String> contextMap = new HashMap<>();

    contextMap.put("\0\0TEST", "\0\0test");
    // Note! This key is actually U+10000, but java treats it as a UTF-16 surrogate pair.
    // UTF-8 encoding should be 0xF0 0x90 0x80 0x80
    contextMap.put("\uD800\uDC00", "UTF-16 surrogate");
    contextMap.put("\uABCD", "\\uABCD");

    ArrayList<KeyBlob> keyBlobs = new ArrayList<>();

    keyBlobs.addAll(
        Arrays.asList(
            new KeyBlob("", new byte[] {}, new byte[] {}), // always first
            new KeyBlob("\0", new byte[] {0}, new byte[] {0}),
            new KeyBlob("\u0081", new byte[] {(byte) 0x81}, new byte[] {(byte) 0x81}),
            new KeyBlob("abc", Hex.decode("deadbeef"), Hex.decode("bad0cafe"))));

    assertEquals(
        "e16344634350fe8cb51e69ec4e0681c84ac7ef2df427bd4de4aefbebcd3ead22"
            + "95f1b15a98ce60699e0efbf69dbbc12e2552b16eff84a6e9b5766ee4d69a7897",
        new String(
            Hex.encode(
                getCacheIdentifier(
                    getCMM("partition ID"),
                    DecryptionMaterialsRequest.newBuilder()
                        .setAlgorithm(
                            CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
                        .setEncryptionContext(contextMap)
                        .setEncryptedDataKeys(keyBlobs)
                        .build()))));
  }

  private byte[] getCacheIdentifier(
      CachingCryptoMaterialsManager cmm, EncryptionMaterialsRequest request) throws Exception {
    Method m =
        CachingCryptoMaterialsManager.class.getDeclaredMethod(
            "getCacheIdentifier", EncryptionMaterialsRequest.class);
    m.setAccessible(true);

    return (byte[]) m.invoke(cmm, request);
  }

  private byte[] getCacheIdentifier(
      CachingCryptoMaterialsManager cmm, DecryptionMaterialsRequest request) throws Exception {
    Method m =
        CachingCryptoMaterialsManager.class.getDeclaredMethod(
            "getCacheIdentifier", DecryptionMaterialsRequest.class);
    m.setAccessible(true);

    return (byte[]) m.invoke(cmm, request);
  }

  private CachingCryptoMaterialsManager getCMM(final String partitionName) {
    return CachingCryptoMaterialsManager.newBuilder()
        .withCache(mock(CryptoMaterialsCache.class))
        .withBackingMaterialsManager(mock(CryptoMaterialsManager.class))
        .withMaxAge(1, TimeUnit.MILLISECONDS)
        .withPartitionId(partitionName)
        .build();
  }
}
