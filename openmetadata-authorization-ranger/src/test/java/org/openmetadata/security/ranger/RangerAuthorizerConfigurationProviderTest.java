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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.hadoop.conf.Configuration;
import org.junit.jupiter.api.Test;
import org.openmetadata.schema.api.security.AuthorizerConfiguration;
import org.openmetadata.schema.api.security.ExtraConfiguration;

public class RangerAuthorizerConfigurationProviderTest {

  @Test
  public void testGetHadoopConfiguration() {
    // Given
    AuthorizerConfiguration authorizerConfiguration =
        new AuthorizerConfiguration()
            .withExtraConfiguration(
                new ExtraConfiguration()
                    .withAdditionalProperty(
                        "hadoop.configuration", "src/test/resources/conf/openmetadata-ranger-hadoop.xml"));
    RangerAuthorizerConfigurationProvider configProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    // When
    Configuration config = configProvider.getHadoopConfiguration();

    // Then
    assertEquals(1, config.size());
    assertEquals("ldap://ldap-test-url:636", config.get("hadoop.security.group.mapping.ldap.url"));
  }

  @Test
  public void testGetHadoopConfigurationFileMissingNoThrows() {
    // Given
    AuthorizerConfiguration authorizerConfiguration =
        new AuthorizerConfiguration()
            .withExtraConfiguration(
                new ExtraConfiguration()
                    .withAdditionalProperty("hadoop.configuration", "some_random_file_that_is_not_here.lie"));
    RangerAuthorizerConfigurationProvider configProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    // When
    Configuration config = configProvider.getHadoopConfiguration();

    // Then
    assertEquals(0, config.size());
  }

  @Test
  public void testGetHadoopConfigurationFileMissingConfigKeyNoThrows() {
    // Given
    AuthorizerConfiguration authorizerConfiguration =
        new AuthorizerConfiguration().withExtraConfiguration(new ExtraConfiguration());
    RangerAuthorizerConfigurationProvider configProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    // When
    Configuration config = configProvider.getHadoopConfiguration();

    // Then
    assertEquals(0, config.size());
  }

  @Test
  public void testGetRangerConfiguration() {
    // Given
    AuthorizerConfiguration authorizerConfiguration =
        new AuthorizerConfiguration()
            .withExtraConfiguration(
                new ExtraConfiguration()
                    .withAdditionalProperty(
                        "ranger.audit.configuration", "src/test/resources/conf/openmetadata-ranger-audit.xml")
                    .withAdditionalProperty(
                        "ranger.security.configuration", "src/test/resources/conf/openmetadata-ranger-security.xml")
                    .withAdditionalProperty(
                        "ranger.policy-manager-ssl.configuration",
                        "src/test/resources/conf/openmetadata-ranger-policymgr-ssl.xml")
                    .withAdditionalProperty("ranger.service.name", "openmetadata-localhost"));
    RangerAuthorizerConfigurationProvider configProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    // When
    Configuration config = configProvider.getRangerPluginConfig();

    // Then
    assertEquals(3, config.size());
    assertEquals("test_value", config.get("xasecure.audit.db.is.enabled"));
    assertEquals(
        "/test_folder/etc/hadoop/conf/ranger-plugin-keystore.jks", config.get("xasecure.policymgr.clientssl.keystore"));
    assertEquals("test_value", config.get("ranger.plugin.openmetadata.service.name"));
  }

  @Test
  public void testGetRangerConfigurationMissingFileNoThrows() {
    // Given
    AuthorizerConfiguration authorizerConfiguration =
        new AuthorizerConfiguration()
            .withExtraConfiguration(
                new ExtraConfiguration()
                    .withAdditionalProperty("ranger.audit.configuration", "some_random_file_that_is_not_here.lie")
                    .withAdditionalProperty("ranger.security.configuration", "some_random_file_that_is_not_here.lie")
                    .withAdditionalProperty(
                        "ranger.policy-manager-ssl.configuration", "some_random_file_that_is_not_here.lie")
                    .withAdditionalProperty("ranger.service.name", "openmetadata-localhost"));
    RangerAuthorizerConfigurationProvider configProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    // When
    Configuration config = configProvider.getRangerPluginConfig();

    // Then
    assertEquals(0, config.size());
  }

  @Test
  public void testGetRangerConfigurationMissingKeyNoThrows() {
    // Given
    AuthorizerConfiguration authorizerConfiguration =
        new AuthorizerConfiguration()
            .withExtraConfiguration(
                new ExtraConfiguration().withAdditionalProperty("ranger.service.name", "openmetadata-localhost"));
    RangerAuthorizerConfigurationProvider configProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    // When
    Configuration config = configProvider.getRangerPluginConfig();

    // Then
    assertEquals(0, config.size());
  }

  @Test
  public void testGetRangerConfigurationMissingServiceNameThrows() {
    // Given
    AuthorizerConfiguration authorizerConfiguration =
        new AuthorizerConfiguration().withExtraConfiguration(new ExtraConfiguration());
    RangerAuthorizerConfigurationProvider configProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    // When / Then
    assertThrows(RuntimeException.class, configProvider::getRangerPluginConfig);
  }
}
