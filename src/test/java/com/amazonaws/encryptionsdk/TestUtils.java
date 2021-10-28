// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import static java.lang.String.format;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.spec.SecretKeySpec;

public class TestUtils {
  public static final CryptoAlgorithm DEFAULT_TEST_CRYPTO_ALG =
      CryptoAlgorithm.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
  public static final CryptoAlgorithm KEY_COMMIT_CRYPTO_ALG =
      CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
  public static final CommitmentPolicy DEFAULT_TEST_COMMITMENT_POLICY =
      CommitmentPolicy.ForbidEncryptAllowDecrypt;

  // Handcrafted message for testing decryption of messages with committed keys
  public static final String messageWithCommitKeyBase64 =
      "AgR4TfvRMU2dVZJbgXIyxeNtbj"
          + "5eIw8BiTDiwsHyQ/Z9wXkAAAABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAz45sc3cDvJZ7D4P3sAM"
          + "KE7d/w8ziQt2C0qHsy1Qu2E2q92eIGE/kLnF/Y003HKvTxx7xv2Zv83YuOdwHML5QIAABAAF88I9zPbUQSf"
          + "OlzLXv+uIY2+m/E6j2PMsbgeHVH/L0wLqQlY+5CL0z3xnNOMIZae/////wAAAAEAAAAAAAAAAAAAAAEAAAA"
          + "OSZBKHHRpTwXOFTQVGapXXj5CwXBMouBB2ucaIJVm";
  public static final JceMasterKey messageWithCommitKeyMasterKey =
      JceMasterKey.getInstance(
          new SecretKeySpec(new byte[32], "AES"), "ProviderName", "KeyId", "AES/GCM/NoPadding");
  public static final String messageWithCommitKeyMessageIdBase64 =
      "TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXk=";
  public static final String messageWithCommitKeyCommitmentBase64 =
      "F88I9zPbUQSfOlzLXv+uIY2+m/E6j2PMsbgeHVH/L0w=";
  public static final String messageWithCommitKeyDEKBase64 =
      "+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0=";
  public static final CryptoAlgorithm messageWithCommitKeyCryptoAlgorithm =
      CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
  public static final String messageWithCommitKeyExpectedResult = "GoodCommitment";

  // Handcrafted message for testing decryption of messages with invalid committed keys
  public static final String invalidMessageWithCommitKeyBase64 =
      "AgR4b1/73X5ErILpj0aSQIx6wNnH"
          + "LEcNLxPzA0m6vYRr7kAAAAABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAypJmXwyizUr3/pyvIAMHL"
          + "U/i5GhZlGayeYC5w/CjUobyGwN4QpeMB0XpNDGTM0f1Zx72V4uM2H5wMjy/hm2wIAABAAAAECAwQFBgcICQ"
          + "oLDA0ODxAREhMUFRYXGBkaGxwdHh/pQM2VSvliz2Qgi5JZf2ta/////wAAAAEAAAAAAAAAAAAAAAEAAAANS"
          + "4Id4+dVHhPrvuJHEiOswo6YGSRjSGX3VDrt+0s=";
  public static final JceMasterKey invalidMessageWithCommitKeyMasterKey =
      JceMasterKey.getInstance(
          new SecretKeySpec(new byte[32], "AES"), "ProviderName", "KeyId", "AES/GCM/NoPadding");

  // avoid spending time generating random data on every test case by caching some random test
  // vectors
  private static final AtomicReference<byte[]> RANDOM_CACHE = new AtomicReference<>(new byte[0]);

  private static byte[] ensureRandomCached(int length) {
    byte[] buf = RANDOM_CACHE.get();
    if (buf.length >= length) {
      return buf;
    }

    byte[] newBuf = new byte[length];
    ThreadLocalRandom.current().nextBytes(newBuf);

    return RANDOM_CACHE.updateAndGet(
        oldBuf -> {
          if (oldBuf.length < newBuf.length) {
            return newBuf;
          } else {
            return oldBuf;
          }
        });
  }

  @FunctionalInterface
  public interface ThrowingRunnable {
    void run() throws Throwable;
  }

  public static void assertThrows(
      Class<? extends Throwable> throwableClass, ThrowingRunnable callback) {
    try {
      callback.run();
    } catch (Throwable t) {
      if (throwableClass.isAssignableFrom(t.getClass())) {
        // ok
        return;
      }
    }

    fail("Expected exception of type " + throwableClass);
  }

  /**
   * Asserts that calling {@code callback} results in a {@code throwableClass} (or sub-class) being
   * thrown which has {@link Throwable#getMessage()} containing {@code message}.
   */
  public static void assertThrows(
      Class<? extends Throwable> throwableClass, String message, ThrowingRunnable callback) {
    try {
      callback.run();
      fail("Expected exception of type " + throwableClass);
    } catch (Throwable t) {
      assertTrue(
          format("Exception of wrong type. Was %s but expected %s", t.getClass(), throwableClass),
          throwableClass.isAssignableFrom(t.getClass()));
      assertTrue(
          format(
              "Exception did not contain the expected message. Actual: \"%s\" did not contain"
                  + " \"%s\"",
              t.getMessage(), message),
          t.getMessage().contains(message));
    }
  }

  public static void assertThrows(ThrowingRunnable callback) {
    assertThrows(Throwable.class, callback);
  }

  /**
   * Asserts that substituting any argument with null causes a NPE to be thrown.
   *
   * <p>Usage:
   *
   * <pre>{@code
   * assertNullChecks(
   *   myAwsCrypto,
   *   "createDecryptingStream",
   *   CryptoMaterialsManager.class, myCMM,
   *   InputStream.class, myIS
   * );
   * }</pre>
   *
   * @param callee
   * @param methodName
   * @param args
   * @throws Exception
   */
  public static void assertNullChecks(
      Object callee,
      String methodName,
      // Class, value
      Object... args)
      throws Exception {
    ArrayList<Class> parameterTypes = new ArrayList<>();
    for (int i = 0; i < args.length; i += 2) {
      parameterTypes.add((Class) args[i]);
    }

    Method m = callee.getClass().getMethod(methodName, parameterTypes.toArray(new Class[0]));

    for (int i = 0; i < args.length / 2; i++) {
      if (args[i * 2 + 1] == null) {
        // already null, which means null is ok here
        continue;
      }

      if (parameterTypes.get(i).isPrimitive()) {
        // can't be null
        continue;
      }

      Object[] modifiedArgs = new Object[args.length / 2];
      for (int j = 0; j < args.length / 2; j++) {
        modifiedArgs[j] = args[j * 2 + 1];
        if (j == i) {
          modifiedArgs[j] = null;
        }
      }

      try {
        m.invoke(callee, modifiedArgs);
        fail("Expected NullPointerException");
      } catch (InvocationTargetException e) {
        if (e.getCause().getClass() == NullPointerException.class) {
          continue;
        }

        fail("Expected NullPointerException, got: " + e.getCause());
      }
    }
  }

  public static byte[] toByteArray(InputStream is) throws IOException {
    byte[] buffer = new byte[4096];

    int offset = 0;
    int rv;
    while (true) {
      rv = is.read(buffer, offset, buffer.length - offset);
      if (rv <= 0) {
        break;
      }

      offset += rv;

      if (offset == buffer.length) {
        if (buffer.length == Integer.MAX_VALUE) {
          throw new IOException("Input data exceeds maximum array size");
        }

        int newSize = Math.toIntExact(Math.min(Integer.MAX_VALUE, 2L * buffer.length));

        byte[] newBuffer = new byte[newSize];
        System.arraycopy(buffer, 0, newBuffer, 0, buffer.length);
        buffer = newBuffer;
      }
    }

    return Arrays.copyOfRange(buffer, 0, offset);
  }

  public static byte[] insecureRandomBytes(int length) {
    byte[] buf = new byte[length];

    System.arraycopy(ensureRandomCached(length), 0, buf, 0, length);

    return buf;
  }

  public static ByteArrayInputStream insecureRandomStream(int length) {
    return new ByteArrayInputStream(ensureRandomCached(length), 0, length);
  }

  public static int[] getFrameSizesToTest(final CryptoAlgorithm cryptoAlg) {
    final int blockSize = cryptoAlg.getBlockSize();
    final int[] frameSizeToTest = {
      0,
      blockSize - 1,
      blockSize,
      blockSize + 1,
      blockSize * 2,
      blockSize * 10,
      blockSize * 10 + 1,
      AwsCrypto.getDefaultFrameSize()
    };
    return frameSizeToTest;
  }

  /**
   * Converts an array of unsigned bytes (represented as int values between 0 and 255 inclusive) to
   * an array of Java primitive type byte, which are by definition signed.
   *
   * @param unsignedBytes An array on unsigned bytes
   * @return An array of signed bytes
   */
  public static byte[] unsignedBytesToSignedBytes(final int[] unsignedBytes) {
    byte[] signedBytes = new byte[unsignedBytes.length];

    for (int i = 0; i < unsignedBytes.length; i++) {
      if (unsignedBytes[i] > 255) {
        throw new IllegalArgumentException("Encountered unsigned byte value > 255");
      }
      signedBytes[i] = (byte) (unsignedBytes[i] & 0xff);
    }

    return signedBytes;
  }

  /**
   * Converts an array of Java primitive type bytes (which are by definition signed) to an array of
   * unsigned bytes (represented as int values between 0 and 255 inclusive).
   *
   * @param signedBytes An array of signed bytes
   * @return An array of unsigned bytes
   */
  public static int[] signedBytesToUnsignedBytes(final byte[] signedBytes) {
    int[] unsignedBytes = new int[signedBytes.length];

    for (int i = 0; i < signedBytes.length; i++) {
      unsignedBytes[i] = ((int) signedBytes[i]) & 0xff;
    }

    return unsignedBytes;
  }
}
