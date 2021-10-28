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

package com.amazonaws.encryptionsdk.exception;

import com.amazonaws.encryptionsdk.MasterKey;

/**
 * This exception is thrown when the SDK attempts to use a {@link MasterKey} which either doesn't
 * exist or to which it doesn't have access.
 */
// @ non_null_by_default
public class NoSuchMasterKeyException extends AwsCryptoException {
  private static final long serialVersionUID = -1L;

  /*@ public normal_behavior
  @   ensures standardThrowable();
  @*/
  // @ pure
  public NoSuchMasterKeyException() {}

  /*@ public normal_behavior
  @   ensures standardThrowable(message);
  @*/
  // @ pure
  public NoSuchMasterKeyException(final String message) {
    super(message);
  }

  /*@ public normal_behavior
  @   ensures standardThrowable(cause);
  @*/
  // @ pure
  public NoSuchMasterKeyException(final Throwable cause) {
    super(cause);
  }

  /*@ public normal_behavior
  @   ensures standardThrowable(message,cause);
  @*/
  // @ pure
  public NoSuchMasterKeyException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /*@ public normal_behavior
  @   ensures standardThrowable(message,cause);
  @*/
  // @ pure // TODO
  public NoSuchMasterKeyException(
      final String message,
      final Throwable cause,
      final boolean enableSuppression,
      final boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
