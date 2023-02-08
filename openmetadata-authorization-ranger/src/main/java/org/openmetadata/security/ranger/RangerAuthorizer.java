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

import java.io.IOException;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.NotImplementedException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.authorization.hadoop.config.RangerPluginConfig;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.openmetadata.schema.api.security.AuthorizerConfiguration;
import org.openmetadata.schema.type.ResourcePermission;
import org.openmetadata.security.Authorizer;
import org.openmetadata.security.OperationContextInterface;
import org.openmetadata.security.ResourceContextInterface;
import org.openmetadata.security.SecurityContextInterface;

@Slf4j
public class RangerAuthorizer implements Authorizer {

  public static final String HADOOP_CONFIGURATION = "hadoop.configuration";
  public static final String RANGER_SECURITY_CONFIGURATION = "ranger.security.configuration";
  public static final String RANGER_AUDIT_CONFIGURATION = "ranger.audit.configuration";
  public static final String RANGER_POLICYMGR_SSL_CONFIGURATION = "ranger.policy-manager-ssl.configuration";
  public static final String RANGER_OPENMETADATA_SERVICE_TYPE = "openmetadata";
  public static final String RANGER_SERVICE_NAME = "ranger.service.name";

  private final RangerBasePlugin rangerPlugin;

  public RangerAuthorizer(AuthorizerConfiguration authorizerConfiguration) {
    Map<String, String> config = authorizerConfiguration.getExtraConfiguration().getAdditionalProperties();

    RangerPluginConfig rangerPluginConfig =
        new RangerPluginConfig(
            RANGER_OPENMETADATA_SERVICE_TYPE, config.get(RANGER_SERVICE_NAME), null, null, null, null);
    List.of(RANGER_SECURITY_CONFIGURATION, RANGER_AUDIT_CONFIGURATION, RANGER_POLICYMGR_SSL_CONFIGURATION)
        .forEach(c -> rangerPluginConfig.addResourceIfReadable(config.get(c)));
    rangerPlugin = new RangerBasePlugin(rangerPluginConfig);
    rangerPlugin.init();
    rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());

    RangerPluginConfig hadoopUserGroupInformationConfiguration =
        new RangerPluginConfig("openmetadata", null, null, null, null, null);
    hadoopUserGroupInformationConfiguration.addResourceIfReadable(config.get(HADOOP_CONFIGURATION));
    UserGroupInformation.setConfiguration(hadoopUserGroupInformationConfiguration);
  }

  @Override
  public List<ResourcePermission> listPermissions(SecurityContextInterface securityContext, String openMetadataUser) {
    throw new NotImplementedException();
  }

  @Override
  public ResourcePermission getPermission(
      SecurityContextInterface securityContext, String openMetadataUser, String openMetadataResourceName) {
    throw new NotImplementedException();
  }

  @Override
  @SneakyThrows
  public ResourcePermission getPermission(
      SecurityContextInterface securityContext, String openMetadataUser, ResourceContextInterface resourceContext) {
    throw new NotImplementedException();
  }

  @Override
  public void authorize(
      SecurityContextInterface securityContext,
      OperationContextInterface operationContext,
      ResourceContextInterface resourceContext)
      throws IOException {
    throw new NotImplementedException();
  }

  @Override
  public void authorizeAdmin(SecurityContextInterface securityContext) {
    throw new NotImplementedException();
  }

  @Override
  public boolean decryptSecret(SecurityContextInterface securityContext) {
    throw new NotImplementedException();
  }
}
