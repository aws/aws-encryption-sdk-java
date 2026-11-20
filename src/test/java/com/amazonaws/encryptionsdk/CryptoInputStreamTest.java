// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static com.amazonaws.encryptionsdk.TestUtils.assertThrows;
import static com.amazonaws.encryptionsdk.TestUtils.insecureRandomBytes;
import static com.amazonaws.encryptionsdk.internal.TestIOUtils.getSha256Hash;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

@RunWith(Enclosed.class)
public class CryptoInputStreamTest {
  private static final SecureRandom RND = new SecureRandom();
  private static final MaterialProviders materialProviders =
      MaterialProviders.builder()
          .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
          .build();
  private static final MasterKey<JceMasterKey> customerMasterKey;
  private static final IKeyring keyring;
  private static final CommitmentPolicy commitmentPolicy = TestUtils.DEFAULT_TEST_COMMITMENT_POLICY;

  static {
    byte[] rawKey = new byte[16];
    RND.nextBytes(rawKey);

    customerMasterKey =
        JceMasterKey.getInstance(
            new SecretKeySpec(rawKey, "AES"), "mockProvider", "mockKey", "AES/GCM/NoPadding");
    keyring =
        materialProviders.CreateRawAesKeyring(
            CreateRawAesKeyringInput.builder()
                .keyName("mockKey")
                .keyNamespace("mockProvider")
                .wrappingAlg(AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16)
                .wrappingKey(ByteBuffer.wrap(new SecretKeySpec(rawKey, "AES").getEncoded()))
                .build());
  }

  private static void testRoundTrip(
      int dataSize,
      Consumer<AwsCrypto> customizer,
      Callback onEncrypt,
      Callback onDecrypt,
      CommitmentPolicy commitmentPolicy)
      throws Exception {
    AwsCrypto awsCrypto = AwsCrypto.builder().withCommitmentPolicy(commitmentPolicy).build();
    customizer.accept(awsCrypto);

    byte[] plaintext = insecureRandomBytes(dataSize);

    ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    onEncrypt.process(awsCrypto, inputStream, outputStream);

    inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    outputStream = new ByteArrayOutputStream();

    onDecrypt.process(awsCrypto, inputStream, outputStream);

    assertArrayEquals(getSha256Hash(plaintext), getSha256Hash(outputStream.toByteArray()));
  }

  private interface Callback {
    void process(AwsCrypto crypto, InputStream inStream, OutputStream outStream) throws Exception;
  }

  private static Callback encryptWithContext(Map<String, String> encryptionContext) {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream =
          awsCrypto.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
    };
  }

  private static Callback encryptWithContextKeyring(Map<String, String> encryptionContext) {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream =
          awsCrypto.createEncryptingStream(keyring, inStream, encryptionContext);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
    };
  }

  private static Callback encryptWithoutContext() {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream =
          awsCrypto.createEncryptingStream(customerMasterKey, inStream);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
    };
  }

  private static Callback encryptWithoutContextKeyring() {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream = awsCrypto.createEncryptingStream(keyring, inStream);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
    };
  }

  private static Callback basicDecrypt(int readLen) {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream =
          awsCrypto.createDecryptingStream(customerMasterKey, inStream);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream, readLen);
    };
  }

  private static Callback basicDecryptKeyring(int readLen) {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream = awsCrypto.createDecryptingStream(keyring, inStream);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream, readLen);
    };
  }

  private static Callback basicDecrypt() {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream =
          awsCrypto.createDecryptingStream(customerMasterKey, inStream);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
    };
  }

  private static Callback basicDecryptKeyring() {
    return (awsCrypto, inStream, outStream) -> {
      final InputStream cryptoStream = awsCrypto.createDecryptingStream(keyring, inStream);

      TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
    };
  }

  @RunWith(Parameterized.class)
  public static class ParameterizedEncryptDecryptTest {
    private final CryptoAlgorithm cryptoAlg;
    private final int byteSize, frameSize, readLen;

    public ParameterizedEncryptDecryptTest(
        CryptoAlgorithm cryptoAlg, int byteSize, int frameSize, int readLen) {
      this.cryptoAlg = cryptoAlg;
      this.byteSize = byteSize;
      this.frameSize = frameSize;
      this.readLen = readLen;
    }

    @Parameterized.Parameters(
        name = "{index}: encryptDecrypt(algorithm={0}, byteSize={1}, frameSize={2}, readLen={3})")
    public static Collection<Object[]> encryptDecryptParams() {
      ArrayList<Object[]> testCases = new ArrayList<>();

      // We'll run more exhaustive tests on the first algorithm, then go lighter weight on the rest.
      boolean firstAlgorithm = true;

      for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
        final int[] frameSizeToTest = TestUtils.getFrameSizesToTest(cryptoAlg);

        // Our bytesToTest and readLenVals arrays tend to have the bigger numbers towards the end -
        // we'll chop off
        // the last few as they take the longest and don't really add that much more coverage.
        int skipLastNSizes;
        if (!FastTestsOnlySuite.isFastTestSuiteActive()) {
          skipLastNSizes = 0;
        } else if (firstAlgorithm) {
          // We'll run more tests for the first algorithm in the list - but not go quite so far as
          // running the
          // 1MB tests.
          skipLastNSizes = 1;
        } else {
          skipLastNSizes = 2;
        }

        // iterate over frame size to test
        for (final int frameSize : frameSizeToTest) {
          int[] bytesToTest = {
            0,
            1,
            frameSize - 1,
            frameSize,
            frameSize + 1,
            (int) (frameSize * 1.5),
            frameSize * 2,
            1000000
          };

          bytesToTest = Arrays.copyOfRange(bytesToTest, 0, bytesToTest.length - skipLastNSizes);

          // iterate over byte size to test
          for (final int byteSize : bytesToTest) {
            int[] readLenVals = {1, byteSize - 1, byteSize, byteSize + 1, byteSize * 2, 1000000};

            readLenVals = Arrays.copyOfRange(readLenVals, 0, readLenVals.length - skipLastNSizes);

            // iterate over read lengths to test
            for (final int readLen : readLenVals) {
              if (byteSize >= 0 && readLen > 0) {
                testCases.add(new Object[] {cryptoAlg, byteSize, frameSize, readLen});
              }
            }
          }
        }

        firstAlgorithm = false;
      }

      return testCases;
    }

    @Test
    public void encryptDecrypt() throws Exception {
      final CommitmentPolicy commitmentPolicy =
          cryptoAlg.isCommitting()
              ? CommitmentPolicy.RequireEncryptRequireDecrypt
              : CommitmentPolicy.ForbidEncryptAllowDecrypt;
      testRoundTrip(
          byteSize,
          awsCrypto -> {
            awsCrypto.setEncryptionAlgorithm(cryptoAlg);
            awsCrypto.setEncryptionFrameSize(frameSize);
          },
          encryptWithoutContext(),
          basicDecrypt(readLen),
          commitmentPolicy);
    }

    @Test
    public void encryptDecryptWithKeyring() throws Exception {
      final CommitmentPolicy commitmentPolicy =
          cryptoAlg.isCommitting()
              ? CommitmentPolicy.RequireEncryptRequireDecrypt
              : CommitmentPolicy.ForbidEncryptAllowDecrypt;
      testRoundTrip(
          byteSize,
          awsCrypto -> {
            awsCrypto.setEncryptionAlgorithm(cryptoAlg);
            awsCrypto.setEncryptionFrameSize(frameSize);
          },
          encryptWithoutContextKeyring(),
          basicDecryptKeyring(readLen),
          commitmentPolicy);
    }
  }

  public static class NonParameterized {
    private AwsCrypto encryptionClient_;

    @Before
    public void setup() throws IOException {
      encryptionClient_ = AwsCrypto.standard();
    }

    @Test
    public void doEncryptDecryptWithoutEncContext() throws Exception {
      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          encryptWithoutContext(),
          basicDecrypt(),
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void doEncryptDecryptWithoutEncContextWithKeyring() throws Exception {
      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          encryptWithoutContextKeyring(),
          basicDecryptKeyring(),
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void encryptBytesDecryptStream() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "encryptBytesDecryptStream");

      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          (AwsCrypto awsCrypto, InputStream inStream, OutputStream outStream) -> {
            ByteArrayOutputStream inbuf = new ByteArrayOutputStream();
            TestIOUtils.copyInStreamToOutStream(inStream, inbuf);

            CryptoResult<byte[], ?> ciphertext =
                awsCrypto.encryptData(customerMasterKey, inbuf.toByteArray(), encryptionContext);

            outStream.write(ciphertext.getResult());
          },
          basicDecrypt(),
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void encryptBytesDecryptStreamWithKeyring() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "encryptBytesDecryptStream");

      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          (AwsCrypto awsCrypto, InputStream inStream, OutputStream outStream) -> {
            ByteArrayOutputStream inbuf = new ByteArrayOutputStream();
            TestIOUtils.copyInStreamToOutStream(inStream, inbuf);

            CryptoResult<byte[], ?> ciphertext =
                awsCrypto.encryptData(keyring, inbuf.toByteArray(), encryptionContext);

            outStream.write(ciphertext.getResult());
          },
          basicDecryptKeyring(),
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void encryptStreamDecryptBytes() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "encryptStreamDecryptBytes");
      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          encryptWithContext(encryptionContext),
          (AwsCrypto awsCrypto, InputStream inStream, OutputStream outStream) -> {
            ByteArrayOutputStream inbuf = new ByteArrayOutputStream();
            TestIOUtils.copyInStreamToOutStream(inStream, inbuf);

            CryptoResult<byte[], ?> ciphertext =
                awsCrypto.decryptData(customerMasterKey, inbuf.toByteArray());

            outStream.write(ciphertext.getResult());
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void encryptStreamDecryptBytesWithKeyring() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "encryptStreamDecryptBytes");
      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          encryptWithContextKeyring(encryptionContext),
          (AwsCrypto awsCrypto, InputStream inStream, OutputStream outStream) -> {
            ByteArrayOutputStream inbuf = new ByteArrayOutputStream();
            TestIOUtils.copyInStreamToOutStream(inStream, inbuf);

            CryptoResult<byte[], ?> ciphertext =
                awsCrypto.decryptData(keyring, inbuf.toByteArray());

            outStream.write(ciphertext.getResult());
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void encryptOSDecryptIS() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "encryptOSDecryptIS");

      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            OutputStream cryptoOS =
                awsCrypto.createEncryptingStream(customerMasterKey, outStream, encryptionContext);
            TestIOUtils.copyInStreamToOutStream(inStream, cryptoOS);
          },
          basicDecrypt(),
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void encryptOSDecryptISWithKeyring() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "encryptOSDecryptIS");

      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            OutputStream cryptoOS =
                awsCrypto.createEncryptingStream(keyring, outStream, encryptionContext);
            TestIOUtils.copyInStreamToOutStream(inStream, cryptoOS);
          },
          basicDecryptKeyring(),
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    private void singleByteCopyLoop(InputStream is, OutputStream os) throws Exception {
      int rv;
      while (-1 != (rv = is.read())) {
        os.write(rv);
      }

      is.close();
      os.close();
    }

    @Test
    public void singleByteRead() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "singleByteRead");

      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            InputStream is =
                awsCrypto.createEncryptingStream(customerMasterKey, inStream, encryptionContext);
            singleByteCopyLoop(is, outStream);
          },
          (awsCrypto, inStream, outStream) -> {
            InputStream is = awsCrypto.createDecryptingStream(customerMasterKey, inStream);
            singleByteCopyLoop(is, outStream);
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void singleByteReadWithKeyring() throws Exception {
      Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "singleByteRead");

      testRoundTrip(
          1_000_000,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            InputStream is = awsCrypto.createEncryptingStream(keyring, inStream, encryptionContext);
            singleByteCopyLoop(is, outStream);
          },
          (awsCrypto, inStream, outStream) -> {
            InputStream is = awsCrypto.createDecryptingStream(keyring, inStream);
            singleByteCopyLoop(is, outStream);
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
    @Test(expected = NullPointerException.class)
    public void whenNullBufferPassed_andNoOffsetArgs_readThrowsNPE()
        throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "nullReadBuffer");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      encryptionInStream.read(null);
    }

    @SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
    @Test(expected = NullPointerException.class)
    public void whenNullBufferPassed_andNoOffsetArgs_readThrowsNPE_keyring()
        throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "nullReadBuffer");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, encryptionContext);

      encryptionInStream.read(null);
    }

    @SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
    @Test(expected = NullPointerException.class)
    public void whenNullBufferPassed_andOffsetArgsPassed_readThrowsNPE()
        throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "nullReadBuffer2");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      encryptionInStream.read(null, 0, 0);
    }

    @SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
    @Test(expected = NullPointerException.class)
    public void whenNullBufferPassed_andOffsetArgsPassed_readThrowsNPE_keyring()
        throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "nullReadBuffer2");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, encryptionContext);

      encryptionInStream.read(null, 0, 0);
    }

    @Test
    public void zeroReadLen() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "zeroReadLen");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      final byte[] tempBytes = new byte[0];
      final int readLen = encryptionInStream.read(tempBytes);
      assertEquals(readLen, 0);
    }

    @Test
    public void zeroReadLen_keyring() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "zeroReadLen");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, encryptionContext);

      final byte[] tempBytes = new byte[0];
      final int readLen = encryptionInStream.read(tempBytes);
      assertEquals(readLen, 0);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test(expected = IllegalArgumentException.class)
    public void negativeReadLen() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "negativeReadLen");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      final byte[] tempBytes = new byte[1];
      encryptionInStream.read(tempBytes, 0, -1);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test(expected = IllegalArgumentException.class)
    public void negativeReadLen_keyring() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "negativeReadLen");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, encryptionContext);

      final byte[] tempBytes = new byte[1];
      encryptionInStream.read(tempBytes, 0, -1);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test(expected = IllegalArgumentException.class)
    public void negativeReadOffset() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "negativeReadOffset");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      byte[] tempBytes = new byte[1];
      encryptionInStream.read(tempBytes, -1, tempBytes.length);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test(expected = IllegalArgumentException.class)
    public void negativeReadOffset_keyring() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "negativeReadOffset");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, encryptionContext);

      byte[] tempBytes = new byte[1];
      encryptionInStream.read(tempBytes, -1, tempBytes.length);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void invalidReadOffset() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "invalidReadOffset");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      final byte[] tempBytes = new byte[100];
      encryptionInStream.read(tempBytes, tempBytes.length + 1, tempBytes.length);
    }

    @Test
    public void noOpStream() throws IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "noOpStream");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(customerMasterKey, inStream, encryptionContext);

      encryptionInStream.close();
    }

    @Test
    public void decryptEmptyFile() throws IOException {
      final InputStream inStream = new ByteArrayInputStream(new byte[0]);
      final InputStream decryptionInStream =
          encryptionClient_.createDecryptingStream(customerMasterKey, inStream);
      final ByteArrayOutputStream outStream = new ByteArrayOutputStream();

      TestIOUtils.copyInStreamToOutStream(decryptionInStream, outStream);

      assertEquals(0, outStream.size());
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void invalidReadOffset_keyring() throws BadCiphertextException, IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "invalidReadOffset");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, encryptionContext);

      final byte[] tempBytes = new byte[100];
      encryptionInStream.read(tempBytes, tempBytes.length + 1, tempBytes.length);
    }

    @Test
    public void noOpStream_keyring() throws IOException {
      final Map<String, String> encryptionContext = new HashMap<>(1);
      encryptionContext.put("ENC", "noOpStream");

      final InputStream inStream = new ByteArrayInputStream(TestUtils.insecureRandomBytes(2048));
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, encryptionContext);

      encryptionInStream.close();
    }

    @Test
    public void decryptEmptyFile_keyring() throws IOException {
      final InputStream inStream = new ByteArrayInputStream(new byte[0]);
      final InputStream decryptionInStream =
          encryptionClient_.createDecryptingStream(keyring, inStream);
      final ByteArrayOutputStream outStream = new ByteArrayOutputStream();

      TestIOUtils.copyInStreamToOutStream(decryptionInStream, outStream);

      assertEquals(0, outStream.size());
    }

    @Test
    public void checkEncContext() throws Exception {
      Map<String, String> setEncryptionContext = new HashMap<>(1);
      setEncryptionContext.put("ENC", "checkEncContext");

      testRoundTrip(
          4096,
          awsCrypto -> {},
          encryptWithContext(setEncryptionContext),
          (crypto, inStream, outStream) -> {
            CryptoInputStream<?> cis = crypto.createDecryptingStream(customerMasterKey, inStream);
            TestIOUtils.copyInStreamToOutStream(cis, outStream);

            // Note that the crypto result might have additional entries in its context, so only
            // check that
            // the entries we set were present, not that the entire map is equal
            CryptoResult<? extends CryptoInputStream<?>, ?> cryptoResult = cis.getCryptoResult();
            setEncryptionContext.forEach(
                (k, v) -> assertEquals(v, cryptoResult.getEncryptionContext().get(k)));
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void checkEncContextKeyring() throws Exception {
      Map<String, String> setEncryptionContext = new HashMap<>(1);
      setEncryptionContext.put("ENC", "checkEncContext");

      testRoundTrip(
          4096,
          awsCrypto -> {},
          encryptWithContextKeyring(setEncryptionContext),
          (crypto, inStream, outStream) -> {
            CryptoInputStream<?> cis = crypto.createDecryptingStream(keyring, inStream);
            TestIOUtils.copyInStreamToOutStream(cis, outStream);

            // Note that the crypto result might have additional entries in its context, so only
            // check that
            // the entries we set were present, not that the entire map is equal
            CryptoResult<? extends CryptoInputStream<?>, ?> cryptoResult = cis.getCryptoResult();
            setEncryptionContext.forEach(
                (k, v) -> assertEquals(v, cryptoResult.getEncryptionContext().get(k)));
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void checkKeyId() throws Exception {
      testRoundTrip(
          4096,
          awsCrypto -> {},
          encryptWithoutContext(),
          (crypto, inStream, outStream) -> {
            CryptoInputStream<?> cis = crypto.createDecryptingStream(customerMasterKey, inStream);
            TestIOUtils.copyInStreamToOutStream(cis, outStream);

            CryptoResult<? extends CryptoInputStream<?>, ?> cryptoResult = cis.getCryptoResult();
            final String returnedKeyId = cryptoResult.getMasterKeys().get(0).getKeyId();

            assertEquals("mockKey", returnedKeyId);
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void checkAvailable() throws IOException {
      final int byteSize = 128;
      final byte[] inBytes = TestIOUtils.generateRandomPlaintext(byteSize);
      final InputStream inStream = new ByteArrayInputStream(inBytes);

      final int frameSize = AwsCrypto.getDefaultFrameSize();
      encryptionClient_.setEncryptionFrameSize(frameSize);

      Map<String, String> setEncryptionContext = new HashMap<>(1);
      setEncryptionContext.put("ENC", "Streaming Test");

      // encryption
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(
              customerMasterKey, inStream, setEncryptionContext);

      assertEquals(byteSize, encryptionInStream.available());
    }

    @Test
    public void checkAvailableKeyring() throws IOException {
      final int byteSize = 128;
      final byte[] inBytes = TestIOUtils.generateRandomPlaintext(byteSize);
      final InputStream inStream = new ByteArrayInputStream(inBytes);

      final int frameSize = AwsCrypto.getDefaultFrameSize();
      encryptionClient_.setEncryptionFrameSize(frameSize);

      Map<String, String> setEncryptionContext = new HashMap<>(1);
      setEncryptionContext.put("ENC", "Streaming Test");

      // encryption
      final InputStream encryptionInStream =
          encryptionClient_.createEncryptingStream(keyring, inStream, setEncryptionContext);

      assertEquals(byteSize, encryptionInStream.available());
    }

    @Test
    public void whenGetResultCalledTooEarly_noExceptionThrown() throws Exception {
      testRoundTrip(
          1024,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createEncryptingStream(customerMasterKey, inStream);

            // can invoke at any time on encrypt
            cryptoStream.getCryptoResult();

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);

            cryptoStream.getCryptoResult();
          },
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createDecryptingStream(customerMasterKey, inStream);

            // this will implicitly read the crypto headers
            cryptoStream.getCryptoResult();

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);

            // still works
            cryptoStream.getCryptoResult();
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void whenGetResultCalledTooEarly_noExceptionThrown_keyring() throws Exception {
      testRoundTrip(
          1024,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createEncryptingStream(keyring, inStream);

            // can invoke at any time on encrypt
            cryptoStream.getCryptoResult();

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);

            cryptoStream.getCryptoResult();
          },
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createDecryptingStream(keyring, inStream);

            // this will implicitly read the crypto headers
            cryptoStream.getCryptoResult();

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);

            // still works
            cryptoStream.getCryptoResult();
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test(expected = BadCiphertextException.class)
    public void whenGetResultInvokedOnEmptyStream_exceptionThrown() throws IOException {
      final CryptoInputStream<?> cryptoStream =
          encryptionClient_.createDecryptingStream(
              customerMasterKey, new ByteArrayInputStream(new byte[0]));

      cryptoStream.getCryptoResult();
    }

    @Test(expected = BadCiphertextException.class)
    public void whenGetResultInvokedOnEmptyStream_exceptionThrown_keyring() throws IOException {
      final CryptoInputStream<?> cryptoStream =
          encryptionClient_.createDecryptingStream(keyring, new ByteArrayInputStream(new byte[0]));

      cryptoStream.getCryptoResult();
    }

    @Test()
    public void encryptUsingCryptoMaterialsManager() throws Exception {
      RecordingMaterialsManager cmm = new RecordingMaterialsManager(customerMasterKey);
      testRoundTrip(
          1024,
          awsCrypto -> {},
          (crypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream = crypto.createEncryptingStream(cmm, inStream);

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);

            assertEquals("bar", cryptoStream.getCryptoResult().getEncryptionContext().get("foo"));
          },
          basicDecrypt(),
          commitmentPolicy);
    }

    @Test()
    public void encryptUsingMplCryptographicMaterialsManager() throws Exception {
      ICryptographicMaterialsManager cmm =
          materialProviders.CreateDefaultCryptographicMaterialsManager(
              CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());
      testRoundTrip(
          1024,
          awsCrypto -> {},
          (crypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream = crypto.createEncryptingStream(cmm, inStream);

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
          },
          basicDecryptKeyring(),
          commitmentPolicy);
    }

    @Test
    public void decryptUsingCryptoMaterialsManager() throws Exception {
      RecordingMaterialsManager cmm = new RecordingMaterialsManager(customerMasterKey);

      testRoundTrip(
          1024,
          awsCrypto -> {},
          encryptWithoutContext(),
          (crypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream = crypto.createDecryptingStream(cmm, inStream);

            assertFalse(cmm.didDecrypt);

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);

            assertTrue(cmm.didDecrypt);
          },
          commitmentPolicy);
    }

    @Test
    public void decryptUsingMplCryptographicMaterialsManager() throws Exception {
      ICryptographicMaterialsManager cmm =
          materialProviders.CreateDefaultCryptographicMaterialsManager(
              CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());

      testRoundTrip(
          1024,
          awsCrypto -> {},
          encryptWithoutContextKeyring(),
          (crypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream = crypto.createDecryptingStream(cmm, inStream);
            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
          },
          commitmentPolicy);
    }

    @Test
    public void whenStreamSizeSetEarly_streamSizePassedToCMM() throws Exception {
      CryptoMaterialsManager cmm = spy(new DefaultCryptoMaterialsManager(customerMasterKey));

      CryptoInputStream<?> is =
          AwsCrypto.standard().createEncryptingStream(cmm, new ByteArrayInputStream(new byte[1]));

      is.setMaxInputLength(1);

      is.read();

      ArgumentCaptor<EncryptionMaterialsRequest> captor =
          ArgumentCaptor.forClass(EncryptionMaterialsRequest.class);
      verify(cmm).getMaterialsForEncrypt(captor.capture());

      assertEquals(1L, captor.getValue().getPlaintextSize());
    }

    @Test
    public void whenStreamSizeSetEarly_andExceeded_exceptionThrown() throws Exception {
      CryptoMaterialsManager cmm = spy(new DefaultCryptoMaterialsManager(customerMasterKey));

      CryptoInputStream<?> is =
          AwsCrypto.standard().createEncryptingStream(cmm, new ByteArrayInputStream(new byte[2]));

      is.setMaxInputLength(1);

      assertThrows(() -> is.read(new byte[65536]));
    }

    @Test
    public void whenStreamSizeSetEarly_andExceeded_exceptionThrown_mplCMM() throws Exception {
      ICryptographicMaterialsManager cmm =
          materialProviders.CreateDefaultCryptographicMaterialsManager(
              CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());

      CryptoInputStream<?> is =
          AwsCrypto.standard().createEncryptingStream(cmm, new ByteArrayInputStream(new byte[2]));

      is.setMaxInputLength(1);

      assertThrows(() -> is.read(new byte[65536]));
    }

    @Test
    public void whenStreamSizeSetLate_andExceeded_exceptionThrown() throws Exception {
      CryptoMaterialsManager cmm = spy(new DefaultCryptoMaterialsManager(customerMasterKey));

      CryptoInputStream<?> is =
          AwsCrypto.standard().createEncryptingStream(cmm, new ByteArrayInputStream(new byte[2]));

      assertThrows(
          () -> {
            is.read();
            is.setMaxInputLength(1);
            is.read(new byte[65536]);
          });
    }

    @Test
    public void whenStreamSizeSetLate_andExceeded_exceptionThrown_mplCMM() throws Exception {
      ICryptographicMaterialsManager cmm =
          materialProviders.CreateDefaultCryptographicMaterialsManager(
              CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());

      CryptoInputStream<?> is =
          AwsCrypto.standard().createEncryptingStream(cmm, new ByteArrayInputStream(new byte[2]));

      assertThrows(
          () -> {
            is.read();
            is.setMaxInputLength(1);
            is.read(new byte[65536]);
          });
    }

    @Test
    public void whenStreamSizeSet_afterBeingExceeded_exceptionThrown() throws Exception {
      CryptoMaterialsManager cmm = spy(new DefaultCryptoMaterialsManager(customerMasterKey));

      CryptoInputStream<?> is =
          AwsCrypto.standard()
              .createEncryptingStream(cmm, new ByteArrayInputStream(new byte[1024 * 1024]));

      assertThrows(
          () -> {
            is.read();
            is.setMaxInputLength(1);
          });
    }

    @Test
    public void whenStreamSizeSet_afterBeingExceeded_exceptionThrown_mplCMM() throws Exception {
      ICryptographicMaterialsManager cmm =
          materialProviders.CreateDefaultCryptographicMaterialsManager(
              CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());

      CryptoInputStream<?> is =
          AwsCrypto.standard()
              .createEncryptingStream(cmm, new ByteArrayInputStream(new byte[1024 * 1024]));

      assertThrows(
          () -> {
            is.read();
            is.setMaxInputLength(1);
          });
    }

    @Test
    public void whenStreamSizeNegative_setSizeThrows() throws Exception {
      CryptoInputStream<?> is =
          AwsCrypto.standard()
              .createEncryptingStream(customerMasterKey, new ByteArrayInputStream(new byte[0]));

      assertThrows(() -> is.setMaxInputLength(-1));
    }

    @Test
    public void whenStreamSizeNegative_setSizeThrows_keyring() throws Exception {
      CryptoInputStream<?> is =
          AwsCrypto.standard()
              .createEncryptingStream(keyring, new ByteArrayInputStream(new byte[0]));

      assertThrows(() -> is.setMaxInputLength(-1));
    }

    @Test
    public void whenStreamSizeSet_roundTripSucceeds() throws Exception {
      testRoundTrip(
          1024,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createEncryptingStream(customerMasterKey, inStream);

            // we happen to know inStream is a ByteArrayInputStream which will give an accurate
            // number
            // of bytes remaining on .available()
            cryptoStream.setMaxInputLength(inStream.available());

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
          },
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createDecryptingStream(customerMasterKey, inStream);

            cryptoStream.setMaxInputLength(inStream.available());

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }

    @Test
    public void whenStreamSizeSet_roundTripSucceeds_keyring() throws Exception {
      testRoundTrip(
          1024,
          awsCrypto -> {},
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createEncryptingStream(keyring, inStream);

            // we happen to know inStream is a ByteArrayInputStream which will give an accurate
            // number
            // of bytes remaining on .available()
            cryptoStream.setMaxInputLength(inStream.available());

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
          },
          (awsCrypto, inStream, outStream) -> {
            final CryptoInputStream<?> cryptoStream =
                awsCrypto.createDecryptingStream(keyring, inStream);

            cryptoStream.setMaxInputLength(inStream.available());

            TestIOUtils.copyInStreamToOutStream(cryptoStream, outStream);
          },
          CommitmentPolicy.RequireEncryptRequireDecrypt);
    }
  }
}
