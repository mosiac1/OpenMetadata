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

import java.util.Set;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.openmetadata.security.SecurityContextInterface;

public class RangerHadoopUserGroupsRolesProvider {

  private final RangerBasePlugin rangerPlugin;

  public RangerHadoopUserGroupsRolesProvider(RangerBasePlugin rangerPlugin) {
    this.rangerPlugin = rangerPlugin;
  }

  public RangerUserGroupsRoles getUserGroupsRoles(SecurityContextInterface securityContextInterface) {
    return getUserGroupsRoles(securityContextInterface, null);
  }

  public RangerUserGroupsRoles getUserGroupsRoles(SecurityContextInterface securityContext, String overrideUserName) {
    if (!UserGroupInformation.isInitialized()) {
      throw new IllegalStateException("UserGroupInformation is not initialized");
    }

    String internalName = overrideUserName != null ? overrideUserName : securityContext.getUserPrincipal().getName();

    UserGroupInformation ugi = UserGroupInformation.createRemoteUser(internalName);
    String user = ugi.getShortUserName();
    Set<String> groups = Set.of(ugi.getGroupNames());
    Set<String> roles = rangerPlugin.getRolesFromUserAndGroups(user, groups);

    return new RangerUserGroupsRoles(user, groups, roles);
  }
}
