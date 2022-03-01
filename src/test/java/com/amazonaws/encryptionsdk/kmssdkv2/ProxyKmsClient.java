package com.amazonaws.encryptionsdk.kmssdkv2;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DependencyTimeoutException;
import software.amazon.awssdk.services.kms.model.DisabledException;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.IncorrectKeyException;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;
import software.amazon.awssdk.services.kms.model.InvalidGrantTokenException;
import software.amazon.awssdk.services.kms.model.InvalidKeyUsageException;
import software.amazon.awssdk.services.kms.model.KeyUnavailableException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.KmsInternalException;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.NotFoundException;

/** This wraps KmsClient since the default implementation is final. */
class ProxyKmsClient implements KmsClient {
  private final KmsClient proxiedClient_;

  ProxyKmsClient(KmsClient kmsClient) {
    proxiedClient_ = kmsClient;
  }

  @Override
  public String serviceName() {
    return proxiedClient_.serviceName();
  }

  @Override
  public void close() {
    proxiedClient_.close();
  }

  @Override
  public DecryptResponse decrypt(DecryptRequest decryptRequest)
      throws NotFoundException, DisabledException, InvalidCiphertextException,
          KeyUnavailableException, IncorrectKeyException, InvalidKeyUsageException,
          DependencyTimeoutException, InvalidGrantTokenException, KmsInternalException,
          KmsInvalidStateException, AwsServiceException, SdkClientException, KmsException {
    return proxiedClient_.decrypt(decryptRequest);
  }

  @Override
  public EncryptResponse encrypt(EncryptRequest encryptRequest)
      throws NotFoundException, DisabledException, KeyUnavailableException,
          DependencyTimeoutException, InvalidKeyUsageException, InvalidGrantTokenException,
          KmsInternalException, KmsInvalidStateException, AwsServiceException, SdkClientException,
          KmsException {
    return proxiedClient_.encrypt(encryptRequest);
  }

  @Override
  public GenerateDataKeyResponse generateDataKey(GenerateDataKeyRequest generateDataKeyRequest)
      throws NotFoundException, DisabledException, KeyUnavailableException,
          DependencyTimeoutException, InvalidKeyUsageException, InvalidGrantTokenException,
          KmsInternalException, KmsInvalidStateException, AwsServiceException, SdkClientException,
          KmsException {
    return proxiedClient_.generateDataKey(generateDataKeyRequest);
  }
}
