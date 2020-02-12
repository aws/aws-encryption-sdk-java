/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.crypto.examples.datakeycaching;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.AwsCryptoResult;
import com.amazonaws.encryptionsdk.DecryptRequest;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.keyrings.StandardKeyrings;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent.KinesisEventRecord;
import com.amazonaws.util.BinaryUtils;

/**
 * Decrypts all incoming Kinesis records and writes records to DynamoDB.
 */
public class LambdaDecryptAndWriteExample implements RequestHandler<KinesisEvent, Void> {
    private static final long MAX_ENTRY_AGE_MILLISECONDS = 600000;
    private static final int MAX_CACHE_ENTRIES = 100;
    private final CachingCryptoMaterialsManager cachingMaterialsManager_;
    private final AwsCrypto crypto_;
    private final Table table_;

    /**
     * This code doesn't set the max bytes or max message security thresholds that are enforced
     * only on data keys used for encryption.
     *
     * @param cmkArn The AWS KMS customer master key to use for decryption
     * @param tableName The name of the DynamoDB table name that stores decrypted messages
     */
    public LambdaDecryptAndWriteExample(final String cmkArn, final String tableName) {
        cachingMaterialsManager_ = CachingCryptoMaterialsManager.newBuilder()
                .withKeyring(StandardKeyrings.awsKms(AwsKmsCmkId.fromString(cmkArn)))
                .withCache(new LocalCryptoMaterialsCache(MAX_CACHE_ENTRIES))
                .withMaxAge(MAX_ENTRY_AGE_MILLISECONDS, TimeUnit.MILLISECONDS)
                .build();
        crypto_ = new AwsCrypto();
        table_ = new DynamoDB(AmazonDynamoDBClientBuilder.defaultClient()).getTable(tableName);
    }

    /**
     * Decrypts Kinesis events and writes the data to DynamoDB
     *
     * @param event The KinesisEvent to decrypt
     * @param context The lambda context
     */
    @Override
    public Void handleRequest(KinesisEvent event, Context context) {
        for (KinesisEventRecord record : event.getRecords()) {
            ByteBuffer ciphertextBuffer = record.getKinesis().getData();
            byte[] ciphertext = BinaryUtils.copyAllBytesFrom(ciphertextBuffer);

            // Decrypt and unpack record
            AwsCryptoResult<byte[]> plaintextResult = crypto_.decrypt(
                    DecryptRequest.builder()
                            .cryptoMaterialsManager(cachingMaterialsManager_)
                            .ciphertext(ciphertext).build());

            // Verify the encryption context value
            String streamArn = record.getEventSourceARN();
            String streamName = streamArn.substring(streamArn.indexOf("/") + 1);
            if (!streamName.equals(plaintextResult.getEncryptionContext().get("stream"))) {
                throw new IllegalStateException("Wrong Encryption Context!");
            }

            // Write record to DynamoDB
            String jsonItem = new String(plaintextResult.getResult(), StandardCharsets.UTF_8);
            table_.putItem(Item.fromJSON(jsonItem));
        }

        return null;
    }
}
