// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import com.amazonaws.crypto.examples.BasicEncryptionExampleTest;
import com.amazonaws.crypto.examples.BasicMultiRegionKeyEncryptionExampleTest;
import com.amazonaws.crypto.examples.DiscoveryDecryptionExampleTest;
import com.amazonaws.crypto.examples.DiscoveryMultiRegionDecryptionExampleTest;
import com.amazonaws.crypto.examples.MultipleCmkEncryptExampleTest;
import com.amazonaws.crypto.examples.RestrictRegionExampleTest;
import com.amazonaws.crypto.examples.SetCommitmentPolicyExampleTest;
import com.amazonaws.crypto.examples.SetEncryptionAlgorithmExampleTest;
import com.amazonaws.crypto.examples.SimpleDataKeyCachingExampleTest;
import com.amazonaws.encryptionsdk.caching.CacheIdentifierTests;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManagerTest;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCacheTest;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCacheThreadStormTest;
import com.amazonaws.encryptionsdk.caching.NullCryptoMaterialsCacheTest;
import com.amazonaws.encryptionsdk.internal.*;
import com.amazonaws.encryptionsdk.jce.JceMasterKeyTest;
import com.amazonaws.encryptionsdk.jce.KeyStoreProviderTest;
import com.amazonaws.encryptionsdk.kms.AwsKmsMrkAwareMasterKeyProviderTest;
import com.amazonaws.encryptionsdk.kms.AwsKmsMrkAwareMasterKeyTest;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilterTest;
import com.amazonaws.encryptionsdk.kms.KMSProviderBuilderMockTests;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProviderTest;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyTest;
import com.amazonaws.encryptionsdk.model.CipherBlockHeadersTest;
import com.amazonaws.encryptionsdk.model.CipherFrameHeadersTest;
import com.amazonaws.encryptionsdk.model.CiphertextHeadersTest;
import com.amazonaws.encryptionsdk.model.DecryptionMaterialsRequestTest;
import com.amazonaws.encryptionsdk.model.EncryptionMaterialsRequestTest;
import com.amazonaws.encryptionsdk.model.KeyBlobTest;
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
  AwsKmsCmkArnInfoTest.class,
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
  BasicMultiRegionKeyEncryptionExampleTest.class,
  DiscoveryDecryptionExampleTest.class,
  DiscoveryMultiRegionDecryptionExampleTest.class,
  MultipleCmkEncryptExampleTest.class,
  RestrictRegionExampleTest.class,
  SimpleDataKeyCachingExampleTest.class,
  SetEncryptionAlgorithmExampleTest.class,
  SetCommitmentPolicyExampleTest.class,
  ParsedCiphertextTest.class,
  AwsKmsMrkAwareMasterKeyProviderTest.class,
  AwsKmsMrkAwareMasterKeyTest.class,
  VersionInfoTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProviderTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProviderTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyTest.class,
})
public class AllTestsSuite {}
