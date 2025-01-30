package com.amazonaws.crypto.examples.mpl_mutation_examples.hierarchy;

import com.amazonaws.crypto.examples.mpl_mutation_examples.Fixtures;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.keystore.model.MRDiscovery;

import javax.annotation.Nullable;

public class KeyStoreProvider {

  public static KeyStore keyStore(@Nullable String kmsArn) {
    KMSConfiguration kmsConfiguration;
    if (kmsArn != null) {
      kmsConfiguration = KMSConfiguration.builder().kmsMRKeyArn(kmsArn).build();
    } else {
      kmsConfiguration =
        KMSConfiguration
          .builder()
          .mrDiscovery(MRDiscovery.builder().region("us-west-2").build())
          .build();
    }
    return KeyStore
      .builder()
      .KeyStoreConfig(
        KeyStoreConfig
          .builder()
          .ddbClient(Fixtures.ddbClientWest2)
          .ddbTableName(Fixtures.TEST_KEYSTORE_NAME)
          .logicalKeyStoreName(Fixtures.TEST_LOGICAL_KEYSTORE_NAME)
          .kmsClient(Fixtures.kmsClientWest2)
          .kmsConfiguration(kmsConfiguration)
          .build()
      )
      .build();
  }
}
