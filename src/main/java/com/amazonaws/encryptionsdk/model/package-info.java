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

/**
 * Contains the classes that implement the defined message format for storing the encrypted content
 * and the data key.
 *
 * <ul>
 *   <li>the CiphertextHeaders class implements the format for the headers that wrap the
 *       (single-block/framed) encrypted content. The data key is stored in this header.
 *   <li>the CipherBlockHeaders class implements the format for the headers that wrap the encrypted
 *       content stored as a single-block.
 *   <li>the CipherFrameHeader class implements the format for the headers that wrap the encrypted
 *       content stored in frames.
 *   <li>the KeyBlob class implements the format for storing the encrypted data key along with the
 *       headers that identify the key provider.
 * </ul>
 */
package com.amazonaws.encryptionsdk.model;
