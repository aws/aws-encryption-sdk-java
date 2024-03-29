package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.kms.KMSProviderBuilderIntegrationTests;
import com.amazonaws.encryptionsdk.kms.MaxEncryptedDataKeysIntegrationTest;
import com.amazonaws.encryptionsdk.kms.XCompatKmsDecryptTest;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
  XCompatKmsDecryptTest.class,
  KMSProviderBuilderIntegrationTests.class,
  MaxEncryptedDataKeysIntegrationTest.class,
  com.amazonaws.encryptionsdk.kms.KMSProviderBuilderIntegrationTests.class,
  com.amazonaws.encryptionsdk.kms.MaxEncryptedDataKeysIntegrationTest.class,
  com.amazonaws.encryptionsdk.kms.XCompatKmsDecryptTest.class
})
public class IntegrationTestSuite {}
