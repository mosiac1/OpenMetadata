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
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResource;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngine;
import org.openmetadata.schema.type.MetadataOperation;

public class RangerOpenmetadataAccessRequest extends RangerAccessRequestImpl {

  public RangerOpenmetadataAccessRequest(
      RangerAccessResource resource, MetadataOperation operation, RangerUserGroupsRoles userGroupsRoles) {
    super(
        resource,
        operation.toString(),
        userGroupsRoles.getUser(),
        userGroupsRoles.getGroups(),
        userGroupsRoles.getRoles());
  }

  public RangerOpenmetadataAccessRequest(
      RangerAccessResource resource,
      MetadataOperation operation,
      String user,
      Set<String> userGroups,
      Set<String> userRoles) {
    super(resource, operation.toString(), user, userGroups, userRoles);
  }

  public RangerOpenmetadataAccessRequest(
      RangerAccessResource resource, MetadataOperation operation, String user, Set<String> userGroups) {
    super(resource, operation.toString(), user, userGroups, null);
  }

  public RangerOpenmetadataAccessRequest(RangerAccessResource resource, String user, Set<String> userGroups) {
    super(resource, RangerPolicyEngine.ANY_ACCESS, user, userGroups, null);
  }
}
