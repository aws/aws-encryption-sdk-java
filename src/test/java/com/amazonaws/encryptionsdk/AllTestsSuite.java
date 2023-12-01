// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.encryptionsdk;

import com.amazonaws.crypto.examples.keyrings.AwsKmsHierarchicalKeyringExampleTest;
import com.amazonaws.crypto.examples.keyrings.AwsKmsRsaKeyringExampleTest;
import com.amazonaws.crypto.examples.keyrings.BasicEncryptionKeyringExampleTest;
import com.amazonaws.crypto.examples.keyrings.DiscoveryDecryptionKeyringExampleTest;
import com.amazonaws.crypto.examples.keyrings.MultiKeyringExampleTest;
import com.amazonaws.crypto.examples.keyrings.RawAesKeyringExampleTest;
import com.amazonaws.crypto.examples.keyrings.RawRsaKeyringExampleTest;
import com.amazonaws.crypto.examples.keyrings.SetEncryptionAlgorithmKeyringExampleTest;
import com.amazonaws.crypto.examples.v2.BasicEncryptionExampleTest;
import com.amazonaws.crypto.examples.v2.BasicMultiRegionKeyEncryptionExampleTest;
import com.amazonaws.crypto.examples.v2.DiscoveryDecryptionExampleTest;
import com.amazonaws.crypto.examples.v2.DiscoveryMultiRegionDecryptionExampleTest;
import com.amazonaws.crypto.examples.v2.MultipleCmkEncryptExampleTest;
import com.amazonaws.crypto.examples.v2.RestrictRegionExampleTest;
import com.amazonaws.crypto.examples.v2.SetCommitmentPolicyExampleTest;
import com.amazonaws.crypto.examples.v2.SetEncryptionAlgorithmExampleTest;
import com.amazonaws.crypto.examples.v2.SimpleDataKeyCachingExampleTest;
import com.amazonaws.encryptionsdk.caching.CacheIdentifierTests;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManagerTest;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCacheTest;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCacheThreadStormTest;
import com.amazonaws.encryptionsdk.caching.NullCryptoMaterialsCacheTest;
import com.amazonaws.encryptionsdk.internal.AwsKmsCmkArnInfoTest;
import com.amazonaws.encryptionsdk.internal.BlockDecryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.BlockEncryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.CipherHandlerTest;
import com.amazonaws.encryptionsdk.internal.CommittedKeyTest;
import com.amazonaws.encryptionsdk.internal.DecryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.EncContextSerializerTest;
import com.amazonaws.encryptionsdk.internal.EncryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.FrameDecryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.FrameEncryptionHandlerTest;
import com.amazonaws.encryptionsdk.internal.PrimitivesParserTest;
import com.amazonaws.encryptionsdk.internal.UtilsTest;
import com.amazonaws.encryptionsdk.internal.VersionInfoTest;
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
  TestVectorGenerator.class,
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
  BasicEncryptionKeyringExampleTest.class,
  DiscoveryDecryptionKeyringExampleTest.class,
  MultiKeyringExampleTest.class,
  MultipleCmkEncryptExampleTest.class,
  RawAesKeyringExampleTest.class,
  RawRsaKeyringExampleTest.class,
  AwsKmsRsaKeyringExampleTest.class,
  DiscoveryDecryptionKeyringExampleTest.class,
  AwsKmsHierarchicalKeyringExampleTest.class,
  SetCommitmentPolicyExampleTest.class,
  SetEncryptionAlgorithmKeyringExampleTest.class,
  ParsedCiphertextTest.class,
  AwsCryptoIntegrationTest.class,
  AwsKmsMrkAwareMasterKeyProviderTest.class,
  AwsKmsMrkAwareMasterKeyTest.class,
  VersionInfoTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProviderTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProviderTest.class,
  com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyTest.class,
})
public class AllTestsSuite {}
