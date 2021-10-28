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

/**
 * This exception is thrown when there are not enough bytes to parse a primitive, a specified number
 * of bytes, or the bytes does not properly represent the desired object.
 */
// @ non_null_by_default
public class ParseException extends AwsCryptoException {
  private static final long serialVersionUID = -1L;

  /** Constructs a new exception with no detail message. */
  /*@ public normal_behavior
  @   ensures standardThrowable();
  @*/
  // @ pure
  public ParseException() {
    super();
  }

  /**
   * Constructs a new exception with the specified detail message.
   *
   * @param message the detail message.
   */
  /*@ public normal_behavior
  @   ensures standardThrowable(message);
  @*/
  // @ pure
  public ParseException(final String message) {
    super(message);
  }

  /**
   * Constructs a new exception with the specified cause and a detail message of <tt>(cause==null ?
   * null : cause.toString())</tt> (which typically contains the class and detail message of
   * <tt>cause</tt>).
   *
   * @param cause the cause (which is saved for later retrieval by the {@link Throwable#getCause()}
   *     method). (A <tt>null</tt> value is permitted, and indicates that the cause is nonexistent
   *     or unknown.)
   */
  /*@ public normal_behavior
  @   ensures standardThrowable(cause);
  @*/
  // @ pure
  public ParseException(final Throwable cause) {
    super(cause);
  }

  /**
   * Constructs a new exception with the specified detail message and cause.
   *
   * <p>Note that the detail message associated with cause is not automatically incorporated in this
   * exception's detail message.
   *
   * @param message the detail message (which is saved for later retrieval by the {@link
   *     Throwable#getMessage()} method).
   * @param cause the cause (which is saved for later retrieval by the {@link Throwable#getCause()}
   *     method). (A <tt>null</tt> value is permitted, and indicates that the cause is nonexistent
   *     or unknown.)
   */
  /*@ public normal_behavior
  @   ensures standardThrowable(message,cause);
  @*/
  // @ pure
  public ParseException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
