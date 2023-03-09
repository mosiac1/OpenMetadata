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

import com.google.common.collect.Streams;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngine;
import org.apache.ranger.plugin.policyengine.RangerResourceACLs;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.openmetadata.schema.type.MetadataOperation;
import org.openmetadata.schema.type.Permission;
import org.openmetadata.schema.type.ResourcePermission;

@Slf4j
public class RangerPermissionsProvider {

  private final RangerBasePlugin rangerPlugin;

  public RangerPermissionsProvider(RangerBasePlugin rangerPlugin) {
    this.rangerPlugin = rangerPlugin;
  }

  public List<ResourcePermission> getPermission(RangerUserGroupsRoles ugr) {
    return rangerPlugin.getServiceDef().getResources().stream()
        .map(r -> getPermission(ugr, new RangerOpenmetadataAccessResource(r)))
        .collect(Collectors.toUnmodifiableList());
  }

  public ResourcePermission getPermission(RangerUserGroupsRoles ugr, RangerOpenmetadataAccessResource resource) {

    RangerAccessRequestImpl req =
        new RangerAccessRequestImpl(
            resource, RangerPolicyEngine.ANY_ACCESS, ugr.getUser(), ugr.getGroups(), ugr.getRoles());

    /*
     Important clarification: RangerBasePlugin#getResourceACLs returns ALL access control rules for a
     resource, not only for the user, groups and roles passed in the request.
     It's the application's responsibility to interpret the results.

     Resource ACLs may also contain AccessResults for access types that are not accepted by the resource
     in the query. This is due to expanding access types which have implied grants.
     e.g.: database_service has the access type ViewAll.
           ViewAll implies ViewUsage, ViewTests, ViewQueries, etc., but database_service does not take these
           access types.
           Resource ACLs for database_service will contain access results for ViewUsage, ViewTests, etc. and
           these need to be filtered out at the application level.
    */
    RangerResourceACLs result = rangerPlugin.getResourceACLs(req);

    return new ResourcePermission()
        .withPermissions(getPermissionFromRangerACLs(result, resource.getRangerResourceName(), ugr))
        .withResource(resource.getOpenMetadataResourceName());
  }

  private List<Permission> getPermissionFromRangerACLs(
      RangerResourceACLs rangerResourceACLs, String rangerResourceName, RangerUserGroupsRoles ugr) {
    Map<String, Map<String, RangerResourceACLs.AccessResult>> userACLs = rangerResourceACLs.getUserACLs();
    Map<String, Map<String, RangerResourceACLs.AccessResult>> groupACLs = rangerResourceACLs.getGroupACLs();
    Map<String, Map<String, RangerResourceACLs.AccessResult>> roleACLs = rangerResourceACLs.getRoleACLs();

    Set<MetadataOperation> supportedAccessTypes =
        rangerPlugin.getServiceDef().getResources().stream()
            .filter(r -> r.getName().equals(rangerResourceName))
            .findFirst()
            .map(RangerServiceDef.RangerResourceDef::getAccessTypeRestrictions)
            .map(s -> s.stream().map(MetadataOperation::fromValue).collect(Collectors.toSet()))
            .orElse(Set.of());

    Map<MetadataOperation, Permission.Access> operationAccessMap =
        supportedAccessTypes.stream().collect(Collectors.toMap(Function.identity(), ignored -> Permission.Access.DENY));

    List<Map.Entry<String, RangerResourceACLs.AccessResult>> rangerAccessAllows =
        Streams.concat(
                userACLs.entrySet().stream()
                    .filter(me -> me.getKey().equals(ugr.getUser()))
                    .flatMap(m -> m.getValue().entrySet().stream()),
                groupACLs.entrySet().stream()
                    .filter(me -> ugr.getGroups().contains(me.getKey()) || me.getKey().equals("public"))
                    .flatMap(m -> m.getValue().entrySet().stream()),
                roleACLs.entrySet().stream()
                    .filter(me -> ugr.getRoles().contains(me.getKey()))
                    .flatMap(m -> m.getValue().entrySet().stream()))
            .filter(me -> me.getValue().getResult() == 1)
            .collect(Collectors.toUnmodifiableList());

    for (var rangerAccessAllow : rangerAccessAllows) {
      try {
        MetadataOperation rangerAccessMetadataOperation = MetadataOperation.fromValue(rangerAccessAllow.getKey());
        if (operationAccessMap.containsKey(rangerAccessMetadataOperation)) {
          operationAccessMap.put(rangerAccessMetadataOperation, Permission.Access.ALLOW);
        }
      } catch (IllegalArgumentException ex) {
        log.warn(
            String.format(
                "getPermissionFromRangerACLs( %s, %s, %s ) ==> Ranger returned access type not recognized by OpenMetadata",
                rangerResourceACLs, rangerResourceName, ugr),
            ex);
      }
    }

    return operationAccessMap.entrySet().stream()
        .map(me -> new Permission().withOperation(me.getKey()).withAccess(me.getValue()))
        .collect(Collectors.toUnmodifiableList());
  }
}
