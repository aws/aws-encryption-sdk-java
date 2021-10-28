package com.amazonaws.encryptionsdk.caching;

import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.DefaultCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import java.util.Collections;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CacheTestFixtures {
  private static final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;

  private static final MasterKey<?> FIXED_KEY =
      JceMasterKey.getInstance(
          new SecretKeySpec(TestUtils.insecureRandomBytes(16), "AES"),
          "prov",
          "keyid",
          "AES/GCM/NoPadding");

  public static EncryptionMaterialsRequest createMaterialsRequest(int index) {
    return EncryptionMaterialsRequest.newBuilder()
        .setContext(Collections.singletonMap("index", Integer.toString(index)))
        .setCommitmentPolicy(commitmentPolicy)
        .build();
  }

  public static EncryptionMaterials createMaterialsResult(EncryptionMaterialsRequest request) {
    return new DefaultCryptoMaterialsManager(FIXED_KEY)
        .getMaterialsForEncrypt(request).toBuilder().setCleartextDataKey(new SentinelKey()).build();
  }

  public static DecryptionMaterialsRequest createDecryptRequest(int index) {
    EncryptionMaterialsRequest mreq = createMaterialsRequest(index);
    EncryptionMaterials mres = createMaterialsResult(mreq);

    return createDecryptRequest(mres);
  }

  public static DecryptionMaterialsRequest createDecryptRequest(EncryptionMaterials mres) {
    return DecryptionMaterialsRequest.newBuilder()
        .setAlgorithm(mres.getAlgorithm())
        .setEncryptionContext(mres.getEncryptionContext())
        .setEncryptedDataKeys(mres.getEncryptedDataKeys())
        .build();
  }

  public static DecryptionMaterials createDecryptResult(DecryptionMaterialsRequest request) {
    DecryptionMaterials realResult =
        new DefaultCryptoMaterialsManager(FIXED_KEY).decryptMaterials(request);
    return realResult.toBuilder()
        .setDataKey(
            new DataKey(
                new SentinelKey(),
                realResult.getDataKey().getEncryptedDataKey(),
                realResult.getDataKey().getProviderInformation(),
                realResult.getDataKey().getMasterKey()))
        .build();
  }

  static EncryptionMaterials createMaterialsResult() {
    return createMaterialsResult(createMaterialsRequest(0));
  }

  // These SentinelKeys let us detect when a particular DecryptionMaterials or EncryptionMaterials
  // is being used, without
  // being concerned about matching all of the fields - we can just use object identity.
  public static class SentinelKey implements SecretKey {
    @Override
    public String getAlgorithm() {
      return "AES";
    }

    @Override
    public String getFormat() {
      return "RAW";
    }

    @Override
    public byte[] getEncoded() {
      return null;
    }
  }
}
