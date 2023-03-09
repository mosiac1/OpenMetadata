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
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessResource;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.openmetadata.schema.api.security.AuthorizerConfiguration;
import org.openmetadata.schema.type.MetadataOperation;
import org.openmetadata.schema.type.ResourcePermission;
import org.openmetadata.security.AuthorizationException;
import org.openmetadata.security.Authorizer;
import org.openmetadata.security.OperationContextInterface;
import org.openmetadata.security.ResourceContextInterface;
import org.openmetadata.security.SecurityContextInterface;

@Slf4j
public class RangerAuthorizer implements Authorizer {

  private final RangerBasePlugin rangerPlugin;
  private final RangerHadoopUserGroupsRolesProvider groupsRolesProvider;

  private final RangerPermissionsProvider permissionsProvider;

  public RangerAuthorizer(AuthorizerConfiguration authorizerConfiguration) {
    RangerAuthorizerConfigurationProvider configurationProvider =
        new RangerAuthorizerConfigurationProvider(authorizerConfiguration);

    UserGroupInformation.setConfiguration(configurationProvider.getHadoopConfiguration());

    rangerPlugin = new RangerBasePlugin(configurationProvider.getRangerPluginConfig());
    rangerPlugin.init();
    rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());

    groupsRolesProvider = new RangerHadoopUserGroupsRolesProvider(rangerPlugin);

    permissionsProvider = new RangerPermissionsProvider(rangerPlugin);
  }

  @Override
  public List<ResourcePermission> listPermissions(SecurityContextInterface securityContext, String openMetadataUser) {
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(securityContext, openMetadataUser);
    return permissionsProvider.getPermission(ugr);
  }

  @Override
  public ResourcePermission getPermission(
      SecurityContextInterface securityContext, String openMetadataUser, String openMetadataResourceName) {
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(securityContext, openMetadataUser);
    return permissionsProvider.getPermission(ugr, new RangerOpenmetadataAccessResource(openMetadataResourceName));
  }

  @Override
  @SneakyThrows
  public ResourcePermission getPermission(
      SecurityContextInterface securityContext, String openMetadataUser, ResourceContextInterface resourceContext) {
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(securityContext, openMetadataUser);
    return permissionsProvider.getPermission(ugr, new RangerOpenmetadataAccessResource(resourceContext));
  }

  @Override
  public void authorize(
      SecurityContextInterface securityContext,
      OperationContextInterface operationContext,
      ResourceContextInterface resourceContext)
      throws IOException {
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(securityContext);

    RangerAccessResource accessResource = new RangerOpenmetadataAccessResource(resourceContext);

    for (MetadataOperation operation : operationContext.getOperations()) {
      RangerAccessRequest req = new RangerOpenmetadataAccessRequest(accessResource, operation, ugr);
      RangerAccessResult result = rangerPlugin.isAccessAllowed(req);
      if (result != null && !result.getIsAllowed()) {
        log.debug(
            "RangerAuthorizer Authorization Rejection => Permission denied by Ranger for request {}, response {}",
            req,
            result);
        throw new AuthorizationException(
            String.format("[RangerAccessRequest=%s] Permission denied by Ranger: %s", req, result));
      }
    }
  }

  @Override
  public void authorizeAdmin(SecurityContextInterface securityContext) {
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(securityContext);
    if (!rangerPlugin.isServiceAdmin(ugr.getUser())) {
      log.debug("RangerAuthorizer Authorization Rejection => User {} is not a Ranger service admin", ugr.getUser());
      throw new AuthorizationException(
          String.format(
              "User %s is not a Ranger service admin for service %s", ugr.getUser(), rangerPlugin.getServiceName()));
    }
  }

  @Override
  public boolean decryptSecret(SecurityContextInterface securityContext) {
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(securityContext);
    return rangerPlugin.isServiceAdmin(ugr.getUser());
  }
}
