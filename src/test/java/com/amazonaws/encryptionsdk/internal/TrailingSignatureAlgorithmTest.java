/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.TestUtils;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import org.junit.Test;

public class TrailingSignatureAlgorithmTest {

  private static final int[] secp256r1PublicFixture_X =
      new int[] {
        163, 132, 202, 41, 50, 135, 193, 159, 67, 19, 186,
        212, 0, 129, 16, 182, 186, 176, 124, 94, 242, 139,
        48, 143, 158, 96, 51, 133, 188, 144, 137, 148
      };

  private static final int[] secp256r1PublicFixture_Y =
      new int[] {
        71, 234, 253, 112, 131, 106, 243, 169, 143, 58, 39,
        222, 47, 211, 230, 90, 139, 163, 54, 249, 187, 115,
        209, 203, 239, 98, 26, 47, 101, 213, 140, 212
      };

  private static final int[] secp2561CompressedFixture =
      new int[] {
        2, 163, 132, 202, 41, 50, 135, 193, 159, 67, 19, 186, 212, 0, 129, 16, 182, 186, 176, 124,
        94, 242, 139, 48, 143, 158, 96, 51, 133, 188, 144, 137, 148
      };

  private static final int[] secp384r1PublicFixture_X =
      new int[] {
        207, 62, 215, 143, 116, 128, 174, 103, 1, 81, 127,
        212, 163, 19, 165, 220, 74, 144, 26, 59, 87, 0,
        214, 47, 66, 73, 152, 227, 196, 81, 14, 28, 58,
        221, 178, 63, 150, 119, 62, 195, 99, 63, 60, 42,
        223, 207, 28, 65
      };

  private static final int[] secp384r1PublicFixture_Y =
      new int[] {
        180, 143, 190, 5, 150, 247, 225, 240, 153, 150, 119, 109, 210, 243, 151, 206, 217, 120, 2,
        171, 75, 180, 31, 4, 91, 78, 206, 217, 241, 119, 55, 230, 216, 23, 237, 101, 21, 89, 132,
        84, 100, 3, 255, 90, 197, 237, 139, 209
      };

  private static final int[] secp384r1CompressedFixture =
      new int[] {
        3, 207, 62, 215, 143, 116, 128, 174, 103, 1, 81, 127, 212, 163, 19, 165, 220, 74, 144, 26,
        59, 87, 0, 214, 47, 66, 73, 152, 227, 196, 81, 14, 28, 58, 221, 178, 63, 150, 119, 62, 195,
        99, 63, 60, 42, 223, 207, 28, 65
      };

  @Test
  public void serializationEquality() throws Exception {
    CryptoAlgorithm algorithm = CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256;

    PublicKey publicKey =
        TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm).generateKey().getPublic();

    String serializedPublicKey =
        TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm).serializePublicKey(publicKey);
    PublicKey deserializedPublicKey =
        TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm)
            .deserializePublicKey(serializedPublicKey);

    assertEquals(publicKey, deserializedPublicKey);

    algorithm = CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

    publicKey = TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm).generateKey().getPublic();

    serializedPublicKey =
        TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm).serializePublicKey(publicKey);
    deserializedPublicKey =
        TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm)
            .deserializePublicKey(serializedPublicKey);

    assertEquals(publicKey, deserializedPublicKey);
  }

  @Test
  public void deserializeSecp384() {
    testDeserialization(
        CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        secp384r1CompressedFixture,
        secp384r1PublicFixture_X,
        secp384r1PublicFixture_Y);
  }

  @Test
  public void serializeSecp384() throws Exception {
    testSerialization(
        CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        "secp384r1",
        secp384r1PublicFixture_X,
        secp384r1PublicFixture_Y,
        secp384r1CompressedFixture);
  }

  @Test
  public void deserializeSecp256() {
    testDeserialization(
        CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        secp2561CompressedFixture,
        secp256r1PublicFixture_X,
        secp256r1PublicFixture_Y);
  }

  @Test
  public void serializeSecp256() throws Exception {
    testSerialization(
        CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        "secp256r1",
        secp256r1PublicFixture_X,
        secp256r1PublicFixture_Y,
        secp2561CompressedFixture);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testBadPoint() {
    byte[] bytes = TestUtils.unsignedBytesToSignedBytes(secp384r1CompressedFixture);
    bytes[20]++;

    String publicKey = Utils.encodeBase64String(bytes);

    TrailingSignatureAlgorithm.forCryptoAlgorithm(
            CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
        .deserializePublicKey(publicKey);
  }

  private void testSerialization(
      CryptoAlgorithm algorithm, String curveName, int[] x, int[] y, int[] expected)
      throws Exception {
    byte[] xBytes = TestUtils.unsignedBytesToSignedBytes(x);
    byte[] yBytes = TestUtils.unsignedBytesToSignedBytes(y);

    final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(curveName));
    ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

    PublicKey publicKey =
        KeyFactory.getInstance("EC")
            .generatePublic(
                new ECPublicKeySpec(
                    new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes)),
                    ecParameterSpec));

    int[] result =
        TestUtils.signedBytesToUnsignedBytes(
            Utils.decodeBase64String(
                TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm)
                    .serializePublicKey(publicKey)));

    assertArrayEquals(expected, result);
  }

  private void testDeserialization(
      CryptoAlgorithm algorithm, int[] compressedKey, int[] expectedX, int[] expectedY) {
    byte[] bytes = TestUtils.unsignedBytesToSignedBytes(compressedKey);

    String publicKey = Utils.encodeBase64String(bytes);

    PublicKey publicKeyDeserialized =
        TrailingSignatureAlgorithm.forCryptoAlgorithm(algorithm).deserializePublicKey(publicKey);

    ECPublicKey desKey = (ECPublicKey) publicKeyDeserialized;

    BigInteger x = desKey.getW().getAffineX();
    BigInteger y = desKey.getW().getAffineY();

    BigInteger expectedXBigInteger =
        new BigInteger(1, TestUtils.unsignedBytesToSignedBytes(expectedX));
    BigInteger expectedYBigInteger =
        new BigInteger(1, TestUtils.unsignedBytesToSignedBytes(expectedY));

    assertEquals(expectedXBigInteger, x);
    assertEquals(expectedYBigInteger, y);
  }
}
