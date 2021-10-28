package com.amazonaws.encryptionsdk.model;

@FunctionalInterface
public interface EncryptionCompletionListener {
  /**
   * Invoked upon encryption completion; MaterialsManagers that need to know the size of the
   * plaintext (e.g. to enforce caching policies) can make use of this.
   *
   * @param plaintextBytes Total number of plaintext bytes encrypted
   */
  void onEncryptDone(long plaintextBytes);
}
