// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import com.amazonaws.crypto.examples.*;
import com.amazonaws.encryptionsdk.caching.*;
import com.amazonaws.encryptionsdk.internal.*;
import com.amazonaws.encryptionsdk.jce.JceMasterKeyTest;
import com.amazonaws.encryptionsdk.jce.KeyStoreProviderTest;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilterTest;
import com.amazonaws.encryptionsdk.kms.KMSProviderBuilderMockTests;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProviderTest;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyTest;
import com.amazonaws.encryptionsdk.model.*;
import com.amazonaws.encryptionsdk.multi.MultipleMasterKeyTest;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  CryptoAlgorithmTest.class,
  CiphertextHeadersTest.class,
  BlockDecryptionHandlerTest.class,
  BlockEncryptionHandlerTest.class,
  CipherHandlerTest.class,
  DecryptionHandlerTest.class,
  EncContextSerializerTest.class,
  EncryptionHandlerTest.class,
  FrameDecryptionHandlerTest.class,
  FrameEncryptionHandlerTest.class,
  PrimitivesParserTest.class,
  KeyStoreProviderTest.class,
  CipherBlockHeadersTest.class,
  CipherFrameHeadersTest.class,
  KeyBlobTest.class,
  DecryptionMaterialsRequestTest.class,
  MultipleMasterKeyTest.class,
  AwsCryptoTest.class,
  CryptoInputStreamTest.class,
  CryptoOutputStreamTest.class,
  TestVectorRunner.class,
  XCompatDecryptTest.class,
  DefaultCryptoMaterialsManagerTest.class,
  NullCryptoMaterialsCacheTest.class,
  CacheIdentifierTests.class,
  CachingCryptoMaterialsManagerTest.class,
  LocalCryptoMaterialsCacheTest.class,
  LocalCryptoMaterialsCacheThreadStormTest.class,
  UtilsTest.class,
  MultipleMasterKeyTest.class,
  KMSProviderBuilderMockTests.class,
  JceMasterKeyTest.class,
  KmsMasterKeyProviderTest.class,
  KmsMasterKeyTest.class,
  DiscoveryFilterTest.class,
  CommittedKeyTest.class,
  EncryptionMaterialsRequestTest.class,
  CommitmentKATRunner.class,
  BasicEncryptionExampleTest.class,
  DiscoveryDecryptionExampleTest.class,
  MultipleCmkEncryptExampleTest.class,
  RestrictRegionExampleTest.class,
  SimpleDataKeyCachingExampleTest.class,
  ParsedCiphertextTest.class,
})
public class AllTestsSuite {}
