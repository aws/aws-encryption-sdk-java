/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.internal;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.apache.commons.lang3.ArrayUtils;

/** A JceKeyCipher based on RSA. */
class RsaJceKeyCipher extends JceKeyCipher {

  private static final Logger LOGGER = Logger.getLogger(RsaJceKeyCipher.class.getName());
  // MGF1 with SHA-224 isn't really supported, but we include it in the regex because we need it
  // for proper handling of the algorithm.
  private static final Pattern SUPPORTED_TRANSFORMATIONS =
      Pattern.compile(
          "RSA/ECB/(?:PKCS1Padding|OAEPWith(SHA-(?:1|224|256|384|512))AndMGF1Padding)",
          Pattern.CASE_INSENSITIVE);
  private final AlgorithmParameterSpec parameterSpec_;
  private final String transformation_;

  RsaJceKeyCipher(PublicKey wrappingKey, PrivateKey unwrappingKey, String transformation) {
    super(wrappingKey, unwrappingKey);

    final Matcher matcher = SUPPORTED_TRANSFORMATIONS.matcher(transformation);
    if (matcher.matches()) {
      final String hashUnknownCase = matcher.group(1);
      if (hashUnknownCase != null) {
        // OAEP mode a.k.a PKCS #1v2
        final String hash = hashUnknownCase.toUpperCase();
        transformation_ = "RSA/ECB/OAEPPadding";

        final MGF1ParameterSpec mgf1Spec;
        switch (hash) {
          case "SHA-1":
            mgf1Spec = MGF1ParameterSpec.SHA1;
            break;
          case "SHA-224":
            LOGGER.warning(transformation + " is not officially supported by the JceMasterKey");
            mgf1Spec = MGF1ParameterSpec.SHA224;
            break;
          case "SHA-256":
            mgf1Spec = MGF1ParameterSpec.SHA256;
            break;
          case "SHA-384":
            mgf1Spec = MGF1ParameterSpec.SHA384;
            break;
          case "SHA-512":
            mgf1Spec = MGF1ParameterSpec.SHA512;
            break;
          default:
            throw new IllegalArgumentException("Unsupported algorithm: " + transformation);
        }
        parameterSpec_ = new OAEPParameterSpec(hash, "MGF1", mgf1Spec, PSource.PSpecified.DEFAULT);
      } else {
        // PKCS #1 v1.x
        transformation_ = transformation;
        parameterSpec_ = null;
      }
    } else {
      LOGGER.warning(transformation + " is not officially supported by the JceMasterKey");
      // Unsupported transformation, just use exactly what we are given
      transformation_ = transformation;
      parameterSpec_ = null;
    }
  }

  @Override
  WrappingData buildWrappingCipher(Key key, Map<String, String> encryptionContext)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(transformation_);
    cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec_);
    return new WrappingData(cipher, ArrayUtils.EMPTY_BYTE_ARRAY);
  }

  @Override
  Cipher buildUnwrappingCipher(
      Key key, byte[] extraInfo, int offset, Map<String, String> encryptionContext)
      throws GeneralSecurityException {
    if (extraInfo.length != offset) {
      throw new IllegalArgumentException("Extra info must be empty for RSA keys");
    }

    final Cipher cipher = Cipher.getInstance(transformation_);
    cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec_);
    return cipher;
  }
}
