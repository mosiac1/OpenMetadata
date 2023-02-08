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

package org.openmetadata.service.security;

import static org.openmetadata.schema.type.Permission.Access.ALLOW;
import static org.openmetadata.service.exception.CatalogExceptionMessage.notAdmin;

import java.io.IOException;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.openmetadata.schema.api.security.AuthorizerConfiguration;
import org.openmetadata.schema.type.ResourcePermission;
import org.openmetadata.security.AuthorizationException;
import org.openmetadata.security.Authorizer;
import org.openmetadata.security.OperationContextInterface;
import org.openmetadata.security.ResourceContextInterface;
import org.openmetadata.security.SecurityContextInterface;
import org.openmetadata.service.security.policyevaluator.PolicyEvaluator;
import org.openmetadata.service.security.policyevaluator.SubjectCache;
import org.openmetadata.service.security.policyevaluator.SubjectContext;

@Slf4j
public class DefaultAuthorizer implements Authorizer {
  private final AuthorizerConfiguration authorizerConfiguration;

  public DefaultAuthorizer(AuthorizerConfiguration config) {
    this.authorizerConfiguration = config;
  }

  @Override
  public void init() {
    LOG.info("Initializing DefaultAuthorizer with config {}", authorizerConfiguration);
  }

  @Override
  public List<ResourcePermission> listPermissions(SecurityContextInterface securityContext, String user) {
    SubjectContext subjectContext = getSubjectContext(securityContext);
    subjectContext = changeSubjectContext(user, subjectContext);
    return subjectContext.isAdmin()
        ? PolicyEvaluator.getResourcePermissions(ALLOW) // Admin has permissions to do all operations.
        : PolicyEvaluator.listPermission(subjectContext);
  }

  @Override
  public ResourcePermission getPermission(SecurityContextInterface securityContext, String user, String resourceType) {
    SubjectContext subjectContext = getSubjectContext(securityContext);
    subjectContext = changeSubjectContext(user, subjectContext);
    return subjectContext.isAdmin()
        ? PolicyEvaluator.getResourcePermission(resourceType, ALLOW) // Admin has permissions to do all operations.
        : PolicyEvaluator.getPermission(subjectContext, resourceType);
  }

  @Override
  public ResourcePermission getPermission(
      SecurityContextInterface securityContext, String user, ResourceContextInterface resourceContext) {
    SubjectContext subjectContext = getSubjectContext(securityContext);
    subjectContext = changeSubjectContext(user, subjectContext);
    return subjectContext.isAdmin()
        ? PolicyEvaluator.getResourcePermission(resourceContext.getResource(), ALLOW) // Admin all permissions
        : PolicyEvaluator.getPermission(subjectContext, resourceContext);
  }

  @Override
  public void authorize(
      SecurityContextInterface securityContext,
      OperationContextInterface operationContext,
      ResourceContextInterface resourceContext)
      throws IOException {
    SubjectContext subjectContext = getSubjectContext(securityContext);
    if (subjectContext.isAdmin()) {
      return;
    }
    PolicyEvaluator.hasPermission(subjectContext, resourceContext, operationContext);
  }

  @Override
  public void authorizeAdmin(SecurityContextInterface securityContext) {
    SubjectContext subjectContext = getSubjectContext(securityContext);
    if (subjectContext.isAdmin()) {
      return;
    }
    throw new AuthorizationException(notAdmin(securityContext.getUserPrincipal().getName()));
  }

  @Override
  public boolean decryptSecret(SecurityContextInterface securityContext) {
    SubjectContext subjectContext = getSubjectContext(securityContext);
    return subjectContext.isAdmin() || subjectContext.isBot();
  }

  public static SubjectContext getSubjectContext(SecurityContextInterface securityContext) {
    if (securityContext == null || securityContext.getUserPrincipal() == null) {
      throw new AuthenticationException("No principal in security context");
    }
    return getSubjectContext(SecurityUtil.getUserName(securityContext.getUserPrincipal()));
  }

  public static SubjectContext getSubjectContext(String userName) {
    return SubjectCache.getInstance().getSubjectContext(userName);
  }

  private SubjectContext changeSubjectContext(String user, SubjectContext loggedInUser) {
    // Asking for some other user's permissions is admin only operation
    if (user != null && !loggedInUser.getUser().getName().equals(user)) {
      if (!loggedInUser.isAdmin()) {
        throw new AuthorizationException(notAdmin(loggedInUser.getUser().getName()));
      }
      LOG.debug("Changing subject context from logged-in user to {}", user);
      return getSubjectContext(user);
    }
    return loggedInUser;
  }
}
