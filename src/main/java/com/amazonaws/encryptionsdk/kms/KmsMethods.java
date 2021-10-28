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

package com.amazonaws.encryptionsdk.kms;

import java.util.List;

/** Methods common to all classes which interact with KMS. */
public interface KmsMethods {
  /** Sets the {@code grantTokens} which should be submitted to KMS when calling it. */
  public void setGrantTokens(List<String> grantTokens);

  /** Returns the grantTokens which this object sends to KMS when calling it. */
  public List<String> getGrantTokens();

  /** Adds {@code grantToken} to the list of grantTokens sent to KMS when this class calls it. */
  public void addGrantToken(String grantToken);
}
