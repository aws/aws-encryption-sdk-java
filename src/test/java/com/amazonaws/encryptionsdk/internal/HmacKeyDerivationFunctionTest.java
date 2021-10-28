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

import static org.junit.Assert.assertArrayEquals;

import com.amazonaws.util.StringUtils;
import org.junit.Test;

public class HmacKeyDerivationFunctionTest {
  private static final testCase[] testCases =
      new testCase[] {
        new testCase(
            "HmacSHA256",
            fromCHex(
                "\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b"
                    + "\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b"),
            fromCHex("\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c"),
            fromCHex("\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9"),
            fromHex(
                "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865")),
        new testCase(
            "HmacSHA256",
            fromCHex(
                "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d"
                    + "\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b"
                    + "\\x1c\\x1d\\x1e\\x1f\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29"
                    + "\\x2a\\x2b\\x2c\\x2d\\x2e\\x2f\\x30\\x31\\x32\\x33\\x34\\x35\\x36\\x37"
                    + "\\x38\\x39\\x3a\\x3b\\x3c\\x3d\\x3e\\x3f\\x40\\x41\\x42\\x43\\x44\\x45"
                    + "\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f"),
            fromCHex(
                "\\x60\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6a\\x6b\\x6c\\x6d"
                    + "\\x6e\\x6f\\x70\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7a\\x7b"
                    + "\\x7c\\x7d\\x7e\\x7f\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89"
                    + "\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97"
                    + "\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5"
                    + "\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf"),
            fromCHex(
                "\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd"
                    + "\\xbe\\xbf\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7\\xc8\\xc9\\xca\\xcb"
                    + "\\xcc\\xcd\\xce\\xcf\\xd0\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7\\xd8\\xd9"
                    + "\\xda\\xdb\\xdc\\xdd\\xde\\xdf\\xe0\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7"
                    + "\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5"
                    + "\\xf6\\xf7\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff"),
            fromHex(
                "B11E398DC80327A1C8E7F78C596A4934"
                    + "4F012EDA2D4EFAD8A050CC4C19AFA97C"
                    + "59045A99CAC7827271CB41C65E590E09"
                    + "DA3275600C2F09B8367793A9ACA3DB71"
                    + "CC30C58179EC3E87C14C01D5C1F3434F"
                    + "1D87")),
        new testCase(
            "HmacSHA256",
            fromCHex(
                "\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b"
                    + "\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b"),
            new byte[0],
            new byte[0],
            fromHex(
                "8DA4E775A563C18F715F802A063C5A31"
                    + "B8A11F5C5EE1879EC3454E5F3C738D2D"
                    + "9D201395FAA4B61A96C8")),
        new testCase(
            "HmacSHA1",
            fromCHex("\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b"),
            fromCHex("\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c"),
            fromCHex("\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9"),
            fromHex(
                "085A01EA1B10F36933068B56EFA5AD81"
                    + "A4F14B822F5B091568A9CDD4F155FDA2"
                    + "C22E422478D305F3F896")),
        new testCase(
            "HmacSHA1",
            fromCHex(
                "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d"
                    + "\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b"
                    + "\\x1c\\x1d\\x1e\\x1f\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29"
                    + "\\x2a\\x2b\\x2c\\x2d\\x2e\\x2f\\x30\\x31\\x32\\x33\\x34\\x35\\x36\\x37"
                    + "\\x38\\x39\\x3a\\x3b\\x3c\\x3d\\x3e\\x3f\\x40\\x41\\x42\\x43\\x44\\x45"
                    + "\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f"),
            fromCHex(
                "\\x60\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6A\\x6B\\x6C\\x6D"
                    + "\\x6E\\x6F\\x70\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7A\\x7B"
                    + "\\x7C\\x7D\\x7E\\x7F\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89"
                    + "\\x8A\\x8B\\x8C\\x8D\\x8E\\x8F\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97"
                    + "\\x98\\x99\\x9A\\x9B\\x9C\\x9D\\x9E\\x9F\\xA0\\xA1\\xA2\\xA3\\xA4\\xA5"
                    + "\\xA6\\xA7\\xA8\\xA9\\xAA\\xAB\\xAC\\xAD\\xAE\\xAF"),
            fromCHex(
                "\\xB0\\xB1\\xB2\\xB3\\xB4\\xB5\\xB6\\xB7\\xB8\\xB9\\xBA\\xBB\\xBC\\xBD"
                    + "\\xBE\\xBF\\xC0\\xC1\\xC2\\xC3\\xC4\\xC5\\xC6\\xC7\\xC8\\xC9\\xCA\\xCB"
                    + "\\xCC\\xCD\\xCE\\xCF\\xD0\\xD1\\xD2\\xD3\\xD4\\xD5\\xD6\\xD7\\xD8\\xD9"
                    + "\\xDA\\xDB\\xDC\\xDD\\xDE\\xDF\\xE0\\xE1\\xE2\\xE3\\xE4\\xE5\\xE6\\xE7"
                    + "\\xE8\\xE9\\xEA\\xEB\\xEC\\xED\\xEE\\xEF\\xF0\\xF1\\xF2\\xF3\\xF4\\xF5"
                    + "\\xF6\\xF7\\xF8\\xF9\\xFA\\xFB\\xFC\\xFD\\xFE\\xFF"),
            fromHex(
                "0BD770A74D1160F7C9F12CD5912A06EB"
                    + "FF6ADCAE899D92191FE4305673BA2FFE"
                    + "8FA3F1A4E5AD79F3F334B3B202B2173C"
                    + "486EA37CE3D397ED034C7F9DFEB15C5E"
                    + "927336D0441F4C4300E2CFF0D0900B52D3B4")),
        new testCase(
            "HmacSHA1",
            fromCHex(
                "\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b"
                    + "\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b"),
            new byte[0],
            new byte[0],
            fromHex("0AC1AF7002B3D761D1E55298DA9D0506" + "B9AE52057220A306E07B6B87E8DF21D0")),
        new testCase(
            "HmacSHA1",
            fromCHex(
                "\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c"
                    + "\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c\\x0c"),
            null,
            new byte[0],
            fromHex(
                "2C91117204D745F3500D636A62F64F0A"
                    + "B3BAE548AA53D423B0D1F27EBBA6F5E5"
                    + "673A081D70CCE7ACFC48"))
      };

  @Test
  public void rfc5869Tests() throws Exception {
    for (int x = 0; x < testCases.length; x++) {
      testCase trial = testCases[x];
      System.out.println("Test case A." + (x + 1));
      HmacKeyDerivationFunction kdf = HmacKeyDerivationFunction.getInstance(trial.algo);
      kdf.init(trial.ikm, trial.salt);
      byte[] result = kdf.deriveKey(trial.info, trial.expected.length);
      assertArrayEquals("Trial A." + x, trial.expected, result);
    }
  }

  @Test
  public void nullTests() throws Exception {
    testCase trial = testCases[0];
    HmacKeyDerivationFunction kdf = HmacKeyDerivationFunction.getInstance(trial.algo);
    kdf.init(trial.ikm, trial.salt);
    // Just ensuring no exceptions are thrown
    kdf.deriveKey(null, 16);
  }

  @Test(expected = IllegalArgumentException.class)
  public void invalidLength() throws Exception {
    testCase trial = testCases[0];
    HmacKeyDerivationFunction kdf = HmacKeyDerivationFunction.getInstance(trial.algo);
    kdf.init(trial.ikm, trial.salt);
    kdf.deriveKey(trial.info, -1);
  }

  @Test
  public void defaultSalt() throws Exception {
    // Tests all the different ways to get the default salt

    testCase trial = testCases[0];
    HmacKeyDerivationFunction kdf1 = HmacKeyDerivationFunction.getInstance(trial.algo);
    kdf1.init(trial.ikm, null);
    HmacKeyDerivationFunction kdf2 = HmacKeyDerivationFunction.getInstance(trial.algo);
    kdf2.init(trial.ikm, new byte[0]);
    HmacKeyDerivationFunction kdf3 = HmacKeyDerivationFunction.getInstance(trial.algo);
    kdf3.init(trial.ikm);
    HmacKeyDerivationFunction kdf4 = HmacKeyDerivationFunction.getInstance(trial.algo);
    kdf4.init(trial.ikm, new byte[32]);

    byte[] testBytes = "Test".getBytes(StringUtils.UTF8);
    byte[] key1 = kdf1.deriveKey(testBytes, 16);
    byte[] key2 = kdf2.deriveKey(testBytes, 16);
    byte[] key3 = kdf3.deriveKey(testBytes, 16);
    byte[] key4 = kdf4.deriveKey(testBytes, 16);

    assertArrayEquals(key1, key2);
    assertArrayEquals(key1, key3);
    assertArrayEquals(key1, key4);
  }

  private static byte[] fromHex(String data) {
    byte[] result = new byte[data.length() / 2];
    for (int x = 0; x < result.length; x++) {
      result[x] = (byte) Integer.parseInt(data.substring(2 * x, 2 * x + 2), 16);
    }
    return result;
  }

  private static byte[] fromCHex(String data) {
    byte[] result = new byte[data.length() / 4];
    for (int x = 0; x < result.length; x++) {
      result[x] = (byte) Integer.parseInt(data.substring(4 * x + 2, 4 * x + 4), 16);
    }
    return result;
  }

  private static class testCase {
    public final String algo;
    public final byte[] ikm;
    public final byte[] salt;
    public final byte[] info;
    public final byte[] expected;

    testCase(String algo, byte[] ikm, byte[] salt, byte[] info, byte[] expected) {
      super();
      this.algo = algo;
      this.ikm = ikm;
      this.salt = salt;
      this.info = info;
      this.expected = expected;
    }
  }
}
