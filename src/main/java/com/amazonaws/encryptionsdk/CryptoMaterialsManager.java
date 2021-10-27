package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;

/**
 * The crypto materials manager is responsible for preparing the cryptographic materials needed to
 * process a request - notably, preparing the cleartext data key and (if applicable) trailing
 * signature keys on both encrypt and decrypt.
 */
public interface CryptoMaterialsManager {
  /**
   * Prepares materials for an encrypt request. The resulting materials result must have a cleartext
   * data key and (if applicable for the crypto algorithm in use) a trailing signature key.
   *
   * <p>The encryption context returned may be different from the one passed in the materials
   * request, and will be serialized (in cleartext) within the encrypted message.
   *
   * @see EncryptionMaterials
   * @see EncryptionMaterialsRequest
   * @param request
   * @return
   */
  EncryptionMaterials getMaterialsForEncrypt(EncryptionMaterialsRequest request);

  DecryptionMaterials decryptMaterials(DecryptionMaterialsRequest request);
}
