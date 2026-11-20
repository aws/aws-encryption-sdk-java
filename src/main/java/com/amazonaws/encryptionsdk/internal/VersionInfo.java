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

package com.amazonaws.encryptionsdk.internal;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.Properties;

/** This class specifies the versioning system for the AWS KMS encryption client. */
public class VersionInfo {
  public static final String USER_AGENT_PREFIX = "AwsCrypto/";
  public static final String UNKNOWN_VERSION = "unknown";
  /*
   * Loads the version of the library
   */
  public static String loadUserAgent() {
    return USER_AGENT_PREFIX + versionNumber();
  }

  /**
   * This returns the API name compatible with the AWS SDK v2
   *
   * @return the name of the library with a tag indicating intended for AWS SDK v2
   */
  public static String apiName() {
    return USER_AGENT_PREFIX.substring(0, USER_AGENT_PREFIX.length() - 1);
  }

  /*
   * String representation of the library version e.g. 2.3.3
   */
  public static String versionNumber() {
    try {
      final Properties properties = new Properties();
      final ClassLoader loader = VersionInfo.class.getClassLoader();
      // Other JARs on the classpath may also define project.properties
      // Enumerate through and find the one for the ESDK
      Enumeration<URL> urls = loader.getResources("project.properties");
      if (urls == null) {
        return UNKNOWN_VERSION;
      }
      while (urls.hasMoreElements()) {
        URL thisURL = urls.nextElement();
        if (thisURL.getPath().contains("aws-encryption-sdk-java")) {
          properties.load(thisURL.openStream());
          break;
        }
      }
      String maybeVersion = properties.getProperty("esdkVersion");
      if (maybeVersion == null) {
        // This should never happen in practice,
        // but is included for robustness.
        return UNKNOWN_VERSION;
      } else {
        return maybeVersion;
      }
    } catch (final IOException ex) {
      return UNKNOWN_VERSION;
    }
  }
}
