/*
 *  Copyright 2021 Collate
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.openmetadata.security.ranger;

import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.ranger.authorization.hadoop.config.RangerPluginConfig;
import org.openmetadata.schema.api.security.AuthorizerConfiguration;

@Slf4j
public class RangerAuthorizerConfigurationProvider {

  public static final String HADOOP_CONFIGURATION = "hadoop.configuration";
  public static final String RANGER_SECURITY_CONFIGURATION = "ranger.security.configuration";
  public static final String RANGER_AUDIT_CONFIGURATION = "ranger.audit.configuration";
  public static final String RANGER_POLICYMGR_SSL_CONFIGURATION = "ranger.policy-manager-ssl.configuration";
  public static final String RANGER_OPENMETADATA_SERVICE_TYPE = "openmetadata";
  public static final String RANGER_SERVICE_NAME = "ranger.service.name";

  private final AuthorizerConfiguration authorizerConfiguration;

  public RangerAuthorizerConfigurationProvider(AuthorizerConfiguration authorizerConfiguration) {
    this.authorizerConfiguration = authorizerConfiguration;
  }

  /**
   * Loads Hadoop configuration from files provided in authorizerConfiguration. Doesn't fail if key is missing from
   * configuration or file is missing.
   */
  public Configuration getHadoopConfiguration() {
    Map<String, String> config = authorizerConfiguration.getExtraConfiguration().getAdditionalProperties();
    Configuration hadoopUserGroupInformationConfiguration = new Configuration(false);

    if (config.containsKey(HADOOP_CONFIGURATION) && !StringUtils.isEmpty(config.get(HADOOP_CONFIGURATION))) {
      Path hadoopConfigFilePath = new Path(config.get(HADOOP_CONFIGURATION));
      hadoopUserGroupInformationConfiguration.addResource(hadoopConfigFilePath);
    } else {
      log.warn(
          "Configuration key [{}] for Hadoop UserGroupInformation is missing or empty, using default configuration",
          HADOOP_CONFIGURATION);
    }

    return hadoopUserGroupInformationConfiguration;
  }

  /**
   * Loads Ranger configuration from files provided in authorizerConfiguration. Loading of configs doesn't fail if keys
   * are missing from authorizerConfiguration or if files are missing.
   */
  public RangerPluginConfig getRangerPluginConfig() {
    List<String> configFileKeys =
        List.of(RANGER_SECURITY_CONFIGURATION, RANGER_AUDIT_CONFIGURATION, RANGER_POLICYMGR_SSL_CONFIGURATION);
    Map<String, String> config = authorizerConfiguration.getExtraConfiguration().getAdditionalProperties();

    if (!config.containsKey(RANGER_SERVICE_NAME) || StringUtils.isEmpty(config.get(RANGER_SERVICE_NAME))) {
      throw new IllegalArgumentException(
          String.format("Missing or empty configuration provided for key %s", RANGER_SERVICE_NAME));
    }

    // appId, clusterName, clusterType and policyEngineOption are set to null in the constructor, RangerPluginConfig
    // will read them from XML the configuration
    RangerPluginConfig rangerPluginConfig =
        new RangerPluginConfig(
            RANGER_OPENMETADATA_SERVICE_TYPE, config.get(RANGER_SERVICE_NAME), null, null, null, null);

    for (String configFileKey : configFileKeys) {
      if (config.containsKey(configFileKey) && !StringUtils.isEmpty(config.get(configFileKey))) {
        rangerPluginConfig.addResourceIfReadable(config.get(configFileKey));
      } else {
        log.warn("Configuration key [{}] for RangerPlugin is missing or empty", configFileKey);
      }
    }

    return rangerPluginConfig;
  }
}
