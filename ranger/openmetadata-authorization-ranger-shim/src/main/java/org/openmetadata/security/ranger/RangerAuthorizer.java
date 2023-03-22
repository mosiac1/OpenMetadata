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
import lombok.extern.slf4j.Slf4j;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;
import org.openmetadata.schema.api.security.AuthorizerConfiguration;
import org.openmetadata.schema.type.ResourcePermission;
import org.openmetadata.security.Authorizer;
import org.openmetadata.security.OperationContextInterface;
import org.openmetadata.security.ResourceContextInterface;
import org.openmetadata.security.SecurityContextInterface;

@Slf4j
public class RangerAuthorizer implements Authorizer {

  private static final String RANGER_PLUGIN_TYPE = "openmetadata";

  private static final String RANGER_OPENMETADATA_AUTHORIZER_IMPL_CLASSNAME =
      "org.openmetadata.security.ranger.RangerAuthorizerImpl";

  private final RangerPluginClassLoader rangerPluginClassLoader;

  private final Authorizer authorizerImpl;

  public RangerAuthorizer(AuthorizerConfiguration authorizerConfiguration) {
    try {
      rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());

      Class<Authorizer> rangerAuthorizerClass =
          (Class<Authorizer>)
              Class.forName(RANGER_OPENMETADATA_AUTHORIZER_IMPL_CLASSNAME, true, rangerPluginClassLoader);

      try (RangerPluginClassLoaderClosableResource loader = new RangerPluginClassLoaderClosableResource()) {
        authorizerImpl =
            rangerAuthorizerClass.getConstructor(AuthorizerConfiguration.class).newInstance(authorizerConfiguration);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public List<ResourcePermission> listPermissions(SecurityContextInterface securityContext, String user) {
    try (RangerPluginClassLoaderClosableResource loader = new RangerPluginClassLoaderClosableResource()) {
      return authorizerImpl.listPermissions(securityContext, user);
    }
  }

  @Override
  public ResourcePermission getPermission(SecurityContextInterface securityContext, String user, String resource) {
    try (RangerPluginClassLoaderClosableResource loader = new RangerPluginClassLoaderClosableResource()) {
      return authorizerImpl.getPermission(securityContext, user, resource);
    }
  }

  @Override
  public ResourcePermission getPermission(
      SecurityContextInterface securityContext, String user, ResourceContextInterface resourceContext) {
    try (RangerPluginClassLoaderClosableResource loader = new RangerPluginClassLoaderClosableResource()) {
      return authorizerImpl.getPermission(securityContext, user, resourceContext);
    }
  }

  @Override
  public void authorize(
      SecurityContextInterface securityContext,
      OperationContextInterface operationContext,
      ResourceContextInterface resourceContext)
      throws IOException {
    try (RangerPluginClassLoaderClosableResource loader = new RangerPluginClassLoaderClosableResource()) {
      authorizerImpl.authorize(securityContext, operationContext, resourceContext);
    }
  }

  @Override
  public void authorizeAdmin(SecurityContextInterface securityContext) {
    try (RangerPluginClassLoaderClosableResource loader = new RangerPluginClassLoaderClosableResource()) {
      authorizerImpl.authorizeAdmin(securityContext);
    }
  }

  @Override
  public boolean decryptSecret(SecurityContextInterface securityContext) {
    try (RangerPluginClassLoaderClosableResource loader = new RangerPluginClassLoaderClosableResource()) {
      return authorizerImpl.decryptSecret(securityContext);
    }
  }

  private class RangerPluginClassLoaderClosableResource implements AutoCloseable {

    public RangerPluginClassLoaderClosableResource() {
      if (rangerPluginClassLoader != null) {
        rangerPluginClassLoader.activate();
      }
    }

    @Override
    public void close() {
      if (rangerPluginClassLoader != null) {
        rangerPluginClassLoader.deactivate();
      }
    }
  }
}
