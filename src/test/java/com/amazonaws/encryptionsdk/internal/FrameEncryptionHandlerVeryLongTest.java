package com.amazonaws.encryptionsdk.internal;

import static org.junit.Assert.fail;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.model.CipherFrameHeaders;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

/*
 * This test exhaustively encrypts a 2^32 frame message, which takes approximately 2-3 hours on my hardware. Because of
 * this long test time, this test is not run as part of the normal suites.
 */
public class FrameEncryptionHandlerVeryLongTest {
  @Test
  public void exhaustiveIVCheck() throws Exception {
    CryptoAlgorithm algorithm = CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;
    FrameEncryptionHandler frameEncryptionHandler_ =
        new FrameEncryptionHandler(
            new SecretKeySpec(new byte[16], "AES"), 12, algorithm, new byte[16], 1);

    byte[] buf = new byte[1024];

    ByteBuffer expectedNonce = ByteBuffer.allocate(12);
    long lastIndex = 1; // starting index for the test
    long lastTS = System.nanoTime();
    for (long i = lastIndex; i <= Constants.MAX_FRAME_NUMBER; i++) {
      Utils.clear(expectedNonce);
      expectedNonce.order(ByteOrder.BIG_ENDIAN);
      expectedNonce.putInt(0);
      expectedNonce.putLong(i);

      if (i != Constants.MAX_FRAME_NUMBER) {
        frameEncryptionHandler_.processBytes(buf, 0, 1, buf, 0);
      } else {
        frameEncryptionHandler_.doFinal(buf, 0);
      }

      CipherFrameHeaders headers = new CipherFrameHeaders();
      headers.setNonceLength(algorithm.getNonceLen());
      headers.deserialize(buf, 0);

      byte[] nonce = headers.getNonce();
      byte[] expectedArray = expectedNonce.array();
      if (!Arrays.equals(nonce, expectedArray)) {
        fail(
            String.format(
                "Index %08x bytes %s != %s",
                i, new String(Hex.encode(nonce)), new String(Hex.encode(expectedArray))));
      }

      if ((i & 0xFFFFF) == 0) {
        // Print progress messages, since this test takes a _very_ long time to run.
        System.out.print(
            String.format(
                "%05.2f%% complete", 100 * (double) i / (double) Constants.MAX_FRAME_NUMBER));
        long newTS = System.nanoTime();
        System.out.println(
            String.format(
                " at a rate of %f/sec\n", (i - lastIndex) / ((newTS - lastTS) / 1_000_000_000.0)));
        lastTS = newTS;
        lastIndex = i;
      }
    }
  }
}
