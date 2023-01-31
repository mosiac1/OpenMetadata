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

package org.openmetadata.security;

import java.io.IOException;
import java.util.List;
import org.openmetadata.schema.type.ResourcePermission;

public interface Authorizer {

  default void init() {}

  /** Returns a list of operations that the authenticated user (subject) can perform */
  List<ResourcePermission> listPermissions(SecurityContextInterface securityContext, String user);

  /** Returns a list of operations that the authenticated user (subject) can perform on a given resource type */
  ResourcePermission getPermission(SecurityContextInterface securityContext, String user, String resource);

  /** Returns a list of operations that the authenticated user (subject) can perform on a given resource */
  ResourcePermission getPermission(
      SecurityContextInterface securityContext, String user, ResourceContextInterface resourceContext);

  void authorize(
      SecurityContextInterface securityContext,
      OperationContextInterface operationContext,
      ResourceContextInterface resourceContext)
      throws IOException;

  void authorizeAdmin(SecurityContextInterface securityContext);

  boolean decryptSecret(SecurityContextInterface securityContext);
}
