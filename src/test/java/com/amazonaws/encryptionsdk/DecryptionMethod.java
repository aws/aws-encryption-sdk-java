package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.internal.SignaturePolicy;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;

public enum DecryptionMethod {
  OneShot {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      return crypto.decryptData(masterKeyProvider, ciphertext).getResult();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      return crypto.decryptData(cmm, ciphertext, encryptionContext).getResult();
    }
  },
  // Note for the record that changing the readLen parameter of copyInStreamToOutStream has minimal
  // effect on the actual data flow when copying from a CryptoInputStream: it will always read
  // from// the
  // underlying input stream with a fixed chunk size (4096 bytes at the time of writing this),
  // independently
  // of how many bytes its asked to read of the decryption result. It's still useful to vary the
  // length to
  // ensure the buffering in the CryptoInputStream works correctly though.
  InputStreamSingleByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in =
          crypto.createDecryptingStream(masterKeyProvider, new ByteArrayInputStream(ciphertext));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, 1);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in =
          crypto.createDecryptingStream(
              cmm, new ByteArrayInputStream(ciphertext), encryptionContext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, 1);
      return out.toByteArray();
    }
  },
  InputStreamSmallByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in =
          crypto.createDecryptingStream(masterKeyProvider, new ByteArrayInputStream(ciphertext));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in =
          crypto.createDecryptingStream(
              cmm, new ByteArrayInputStream(ciphertext), encryptionContext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }
  },
  InputStreamWholeMessageChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in =
          crypto.createDecryptingStream(masterKeyProvider, new ByteArrayInputStream(ciphertext));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, ciphertext.length);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in =
          crypto.createDecryptingStream(
              cmm, new ByteArrayInputStream(ciphertext), encryptionContext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, ciphertext.length);
      return out.toByteArray();
    }
  },
  UnsignedMessageInputStreamSingleByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in =
          crypto.createUnsignedMessageDecryptingStream(
              masterKeyProvider, new ByteArrayInputStream(ciphertext));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, 1);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in =
          crypto.createUnsignedMessageDecryptingStream(
              cmm, new ByteArrayInputStream(ciphertext), encryptionContext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, 1);
      return out.toByteArray();
    }

    @Override
    public SignaturePolicy signaturePolicy() {
      return SignaturePolicy.AllowEncryptForbidDecrypt;
    }
  },
  UnsignedMessageInputStreamSmallByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in =
          crypto.createUnsignedMessageDecryptingStream(
              masterKeyProvider, new ByteArrayInputStream(ciphertext));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in =
          crypto.createUnsignedMessageDecryptingStream(
              cmm, new ByteArrayInputStream(ciphertext), encryptionContext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }

    @Override
    public SignaturePolicy signaturePolicy() {
      return SignaturePolicy.AllowEncryptForbidDecrypt;
    }
  },
  UnsignedMessageInputStreamWholeMessageChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in =
          crypto.createUnsignedMessageDecryptingStream(
              masterKeyProvider, new ByteArrayInputStream(ciphertext));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, ciphertext.length);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in =
          crypto.createUnsignedMessageDecryptingStream(
              cmm, new ByteArrayInputStream(ciphertext), encryptionContext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      TestIOUtils.copyInStreamToOutStream(in, out, ciphertext.length);
      return out.toByteArray();
    }

    @Override
    public SignaturePolicy signaturePolicy() {
      return SignaturePolicy.AllowEncryptForbidDecrypt;
    }
  },
  OutputStreamSingleByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut = crypto.createDecryptingStream(masterKeyProvider, out);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, 1);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut = crypto.createDecryptingStream(cmm, out, encryptionContext);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, 1);
      return out.toByteArray();
    }
  },
  OutputStreamSmallByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut = crypto.createDecryptingStream(masterKeyProvider, out);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut = crypto.createDecryptingStream(cmm, out, encryptionContext);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }
  },
  OutputStreamWholeMessageChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut = crypto.createDecryptingStream(masterKeyProvider, out);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, ciphertext.length);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut = crypto.createDecryptingStream(cmm, out, encryptionContext);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, ciphertext.length);
      return out.toByteArray();
    }
  },
  UnsignedMessageOutputStreamSingleByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut =
          crypto.createUnsignedMessageDecryptingStream(masterKeyProvider, out);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, 1);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut =
          crypto.createUnsignedMessageDecryptingStream(cmm, out, encryptionContext);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, 1);
      return out.toByteArray();
    }

    @Override
    public SignaturePolicy signaturePolicy() {
      return SignaturePolicy.AllowEncryptForbidDecrypt;
    }
  },
  UnsignedMessageOutputStreamSmallByteChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut =
          crypto.createUnsignedMessageDecryptingStream(masterKeyProvider, out);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }

    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut =
          crypto.createUnsignedMessageDecryptingStream(cmm, out, encryptionContext);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, SMALL_CHUNK_SIZE);
      return out.toByteArray();
    }

    @Override
    public SignaturePolicy signaturePolicy() {
      return SignaturePolicy.AllowEncryptForbidDecrypt;
    }
  },
  UnsignedMessageOutputStreamWholeMessageChunks {
    @Override
    public byte[] decryptMessage(
        AwsCrypto crypto, MasterKeyProvider masterKeyProvider, byte[] ciphertext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut =
          crypto.createUnsignedMessageDecryptingStream(masterKeyProvider, out);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, ciphertext.length);
      return out.toByteArray();
    }

    public byte[] decryptMessage(
        AwsCrypto crypto,
        ICryptographicMaterialsManager cmm,
        byte[] ciphertext,
        Map<String, String> encryptionContext)
        throws IOException {
      InputStream in = new ByteArrayInputStream(ciphertext);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      OutputStream decryptingOut =
          crypto.createUnsignedMessageDecryptingStream(cmm, out, encryptionContext);
      TestIOUtils.copyInStreamToOutStream(in, decryptingOut, ciphertext.length);
      return out.toByteArray();
    }

    @Override
    public SignaturePolicy signaturePolicy() {
      return SignaturePolicy.AllowEncryptForbidDecrypt;
    }
  };

  // A semi-arbitrary chunk size just to have at least one non-boundary input, and something
  // that will span at least some message segments.
  private static final int SMALL_CHUNK_SIZE = 100;

  public abstract byte[] decryptMessage(
      AwsCrypto crypto, MasterKeyProvider<?> masterKeyProvider, byte[] ciphertext)
      throws IOException;

  public abstract byte[] decryptMessage(
      AwsCrypto crypto,
      ICryptographicMaterialsManager cmm,
      byte[] ciphertext,
      Map<String, String> encryptionContext)
      throws IOException;

  public SignaturePolicy signaturePolicy() {
    return SignaturePolicy.AllowEncryptAllowDecrypt;
  }
}
