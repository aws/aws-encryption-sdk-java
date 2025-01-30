package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Constants;
import com.amazonaws.crypto.examples.mpl_mutation_examples.DdbHelper;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.*;

import java.util.List;
import java.util.Map;

public class ValidateKeyStoreItem {

  public static String ValidateActiveItem(
    String branchKeyId,
    KeyStore keyStore
  ) {
    GetActiveBranchKeyOutput output = keyStore.GetActiveBranchKey(
      GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build()
    );
    return output.branchKeyMaterials().branchKeyVersion();
  }

  public static boolean ValidateVersionItem(
    String branchKeyId,
    String version,
    KeyStore keyStore
  ) {
    GetBranchKeyVersionOutput output = keyStore.GetBranchKeyVersion(
      GetBranchKeyVersionInput
        .builder()
        .branchKeyIdentifier(branchKeyId)
        .branchKeyVersion(version)
        .build()
    );
    return true;
  }

  public static boolean ValidateBeaconItem(
    String branchKeyId,
    KeyStore keyStore
  ) {
    GetBeaconKeyOutput output = keyStore.GetBeaconKey(
      GetBeaconKeyInput.builder().branchKeyIdentifier(branchKeyId).build()
    );
    return true;
  }

  public static void ValidateBranchKey(String branchKeyId, KeyStore keyStore) {
    final List<Map<String, AttributeValue>> allBKItems =
      DdbHelper.QueryForAllBkItemsDDBKeys(branchKeyId, null, null, null);
    for (Map<String, AttributeValue> item : allBKItems) {
      validateBranchKeyItem(keyStore, item);
    }
  }

  private static boolean validateBranchKeyItem(
    KeyStore keyStore,
    Map<String, AttributeValue> bkDdbKey
  ) {
    String bkId = bkDdbKey.get(Constants.BRANCH_KEY_ID).s();
    String typeStr = bkDdbKey.get(Constants.TYPE).s();
    assert bkId != null : "bkDdbKey must have " + Constants.BRANCH_KEY_ID;
    assert typeStr != null : "typeStr must have " + Constants.TYPE;
    if (typeStr.startsWith(Constants.TYPE_VERSION)) {
      String version = typeStr.substring(Constants.TYPE_VERSION.length());
      assert StringUtils.isNotBlank(version) : "version is malformed " +
      Constants.TYPE;
      ValidateVersionItem(bkId, version, keyStore);
    } else {
      switch (typeStr) {
        case Constants.TYPE_ACTIVE:
          ValidateActiveItem(bkId, keyStore);
          break;
        case Constants.TYPE_BEACON:
          ValidateBeaconItem(bkId, keyStore);
          break;
        default:
          throw new IllegalArgumentException("Invalid type " + typeStr);
      }
    }
    return true;
  }
}
