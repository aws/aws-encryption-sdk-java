package com.amazonaws.encryptionsdk.internal;

import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * A {@link MessageCryptoHandler} that delegates to another MessageCryptoHandler, which is created
 * at the last possible moment. Typically, this is used in order to defer the creation of the data
 * key (and associated request to the {@link com.amazonaws.encryptionsdk.CryptoMaterialsManager}
 * until the max message size is known.
 */
@NotThreadSafe
public class LazyMessageCryptoHandler implements MessageCryptoHandler {
  private Function<LateBoundInfo, MessageCryptoHandler> delegateFactory;
  private MessageCryptoHandler delegate;
  private long maxInputSize = -1;

  public static final class LateBoundInfo {
    private final long maxInputSize;

    private LateBoundInfo(long maxInputSize) {
      this.maxInputSize = maxInputSize;
    }

    public long getMaxInputSize() {
      return maxInputSize;
    }
  }

  public LazyMessageCryptoHandler(Function<LateBoundInfo, MessageCryptoHandler> delegateFactory) {
    this.delegateFactory = delegateFactory;
    this.delegate = null;
  }

  private MessageCryptoHandler getDelegate() {
    if (delegate == null) {
      delegate = delegateFactory.apply(new LateBoundInfo(maxInputSize));
      if (maxInputSize != -1) {
        delegate.setMaxInputLength(maxInputSize);
      }

      // Release references to the delegate factory, now that we're done with it.
      delegateFactory = null;
    }

    return delegate;
  }

  @Override
  public void setMaxInputLength(long size) {
    if (size < 0) {
      throw new IllegalArgumentException("Max input size must be non-negative");
    }

    if (delegate == null) {
      if (maxInputSize == -1 || maxInputSize > size) {
        maxInputSize = size;
      }
    } else {
      delegate.setMaxInputLength(size);
    }
  }

  @Override
  public boolean isComplete() {
    // If we haven't generated the delegate, we're definitely not done yet.
    return delegate != null && delegate.isComplete();
  }

  /* Operations which autovivify the delegate */

  @Override
  public Map<String, String> getEncryptionContext() {
    return getDelegate().getEncryptionContext();
  }

  @Override
  public CiphertextHeaders getHeaders() {
    return getDelegate().getHeaders();
  }

  @Override
  public ProcessingSummary processBytes(byte[] in, int inOff, int inLen, byte[] out, int outOff) {
    return getDelegate().processBytes(in, inOff, inLen, out, outOff);
  }

  @Override
  public List<? extends MasterKey<?>> getMasterKeys() {
    return getDelegate().getMasterKeys();
  }

  @Override
  public int doFinal(byte[] out, int outOff) {
    return getDelegate().doFinal(out, outOff);
  }

  @Override
  public int estimateOutputSize(int inLen) {
    return getDelegate().estimateOutputSize(inLen);
  }

  @Override
  public int estimatePartialOutputSize(int inLen) {
    return getDelegate().estimatePartialOutputSize(inLen);
  }

  @Override
  public int estimateFinalOutputSize() {
    return getDelegate().estimateFinalOutputSize();
  }
}
