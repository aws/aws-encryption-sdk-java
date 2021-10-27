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
 * Contains the internal classes that handle the cryptographic defined by the message formats and
 * algorithms. The package also includes auxiliary classes that implement serialization of
 * encryption context, parser for deserializing bytes into primitives, and generation of random
 * bytes.
 *
 * <p><em>No classes in this package are intended for public consumption. They may be changed at any
 * time without concern for API compatibility.</em>
 *
 * <ul>
 *   <li>the CryptoHandler interface that defines the contract for the methods that must be
 *       implemented by classes that perform encryption and decryption in this library.
 *   <li>the EncryptionHandler and DecryptionHandler classes handle the creation and parsing of the
 *       ciphertext headers as described in the message format. These two classes delegate the
 *       actual encryption and decryption of content to the Block and Frame handlers.
 *   <li>the BlockEncryptionHandler and BlockDecryptionHandler classes handle the encryption and
 *       decryption of content stored as a single-block as described in the message format.
 *   <li>the FrameEncryptionHandler and FrameDecryptionHandler classes handle the encryption and
 *       decryption of content stored as frames as described in the message format.
 *   <li>the CipherHandler that provides methods to cryptographically transform bytes using a block
 *       cipher. Currently, it only uses AES-GCM block cipher.
 *   <li>the EncContextSerializer provides methods to serialize a map containing the encryption
 *       context into bytes, and deserialize bytes into a map containing the encryption context.
 *   <li>the PrimitivesParser provides methods to parse primitive types from bytes. These methods
 *       are used by deserialization code.
 *   <li>the ContentAadGenerator provides methods to generate the Additional Authenticated Data
 *       (AAD) used in encrypting the content.
 *   <li>the Constants class that contains the constants and default values used in the library.
 * </ul>
 */
package com.amazonaws.encryptionsdk.internal;
