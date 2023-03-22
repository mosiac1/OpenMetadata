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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerResourceACLs;
import org.apache.ranger.plugin.policyevaluator.RangerPolicyEvaluator;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openmetadata.schema.type.MetadataOperation;
import org.openmetadata.schema.type.Permission;
import org.openmetadata.schema.type.ResourcePermission;

@ExtendWith(MockitoExtension.class)
public class RangerPermissionsProviderTest {

  @Mock private RangerBasePlugin rangerPluginMock;

  private RangerPermissionsProvider permissionsProvider;

  private static RangerServiceDef serviceDef;

  private static final RangerResourceACLs.AccessResult allowed =
      new RangerResourceACLs.AccessResult(RangerPolicyEvaluator.ACCESS_ALLOWED, null);

  private static Map<String, RangerResourceACLs.AccessResult> allViewAccessResults;

  private static Map<String, RangerResourceACLs.AccessResult> allEditAccessResults;

  private static Map<String, RangerResourceACLs.AccessResult> allAccessResults;

  @BeforeAll
  public static void setUpClass() {
    ObjectMapper mapper = new ObjectMapper();
    try {
      serviceDef =
          mapper.readValue(
              RangerPermissionsProviderTest.class.getResource("/ranger-servicedef-openmetadata.json"),
              RangerServiceDef.class);
    } catch (IOException e) {
      throw new IllegalArgumentException("Failed to read ranger-servicedef-openmetadata.json", e);
    }
    assertNotNull(serviceDef);

    allAccessResults =
        serviceDef.getAccessTypes().stream()
            .collect(Collectors.toMap(RangerServiceDef.RangerAccessTypeDef::getName, ignored -> allowed));

    allViewAccessResults =
        serviceDef.getAccessTypes().stream()
            .filter(at -> at.getName().contains("View"))
            .collect(Collectors.toMap(RangerServiceDef.RangerAccessTypeDef::getName, ignored -> allowed));

    allEditAccessResults =
        serviceDef.getAccessTypes().stream()
            .filter(at -> at.getName().contains("Edit"))
            .collect(Collectors.toMap(RangerServiceDef.RangerAccessTypeDef::getName, ignored -> allowed));
  }

  @BeforeEach
  public void setUpTest() {
    when(rangerPluginMock.getServiceDef()).thenReturn(serviceDef);
    permissionsProvider = new RangerPermissionsProvider(rangerPluginMock);
  }

  @ParameterizedTest
  @MethodSource("provideGetPermissionsTestValues")
  public void testGetPermissionsFromUserAndGroups(
      RangerUserGroupsRoles ugr, RangerResourceACLs resourceACLs, List<Permission> expectedPermissions) {
    // Given
    when(rangerPluginMock.getResourceACLs(any())).thenReturn(resourceACLs);

    // When
    ResourcePermission res =
        permissionsProvider.getPermission(ugr, new RangerOpenmetadataAccessResource("databaseService"));

    // Then
    assertEquals("databaseService", res.getResource());
    assertEquals(expectedPermissions.size(), res.getPermissions().size());
    assertTrue(expectedPermissions.containsAll(res.getPermissions()));
    assertTrue(res.getPermissions().containsAll(expectedPermissions));

    verify(rangerPluginMock).getResourceACLs(any());
  }

  private static Stream<Arguments> provideGetPermissionsTestValues() {
    RangerUserGroupsRoles justAlice = new RangerUserGroupsRoles("alice", Set.of(), Set.of());
    RangerUserGroupsRoles moderatorAlice = new RangerUserGroupsRoles("alice", Set.of("moderator"), Set.of());
    RangerUserGroupsRoles consumerAlice = new RangerUserGroupsRoles("alice", Set.of(), Set.of("metadata-consumer"));

    RangerResourceACLs aliceAllowAllACLs = mock(RangerResourceACLs.class);
    when(aliceAllowAllACLs.getUserACLs()).thenReturn(Map.of("alice", allAccessResults));
    when(aliceAllowAllACLs.getGroupACLs()).thenReturn(Map.of());
    when(aliceAllowAllACLs.getRoleACLs()).thenReturn(Map.of());

    RangerResourceACLs aliceAllowViewACLs = mock(RangerResourceACLs.class);
    when(aliceAllowViewACLs.getUserACLs()).thenReturn(Map.of("alice", allViewAccessResults));
    when(aliceAllowViewACLs.getGroupACLs()).thenReturn(Map.of());
    when(aliceAllowViewACLs.getRoleACLs()).thenReturn(Map.of());

    RangerResourceACLs aliceAllowViewAndAdminACLs = mock(RangerResourceACLs.class);
    when(aliceAllowViewAndAdminACLs.getUserACLs()).thenReturn(Map.of("alice", allViewAccessResults));
    when(aliceAllowViewAndAdminACLs.getGroupACLs()).thenReturn(Map.of("admin", allAccessResults));
    when(aliceAllowViewAndAdminACLs.getRoleACLs()).thenReturn(Map.of());

    RangerResourceACLs publicAllowViewACLs = mock(RangerResourceACLs.class);
    when(publicAllowViewACLs.getUserACLs()).thenReturn(Map.of());
    when(publicAllowViewACLs.getGroupACLs()).thenReturn(Map.of("public", allViewAccessResults));
    when(publicAllowViewACLs.getRoleACLs()).thenReturn(Map.of());

    RangerResourceACLs publicAndModeratorACLs = mock(RangerResourceACLs.class);
    when(publicAndModeratorACLs.getUserACLs()).thenReturn(Map.of());
    when(publicAndModeratorACLs.getGroupACLs())
        .thenReturn(Map.of("public", allViewAccessResults, "moderator", allEditAccessResults));
    when(publicAndModeratorACLs.getRoleACLs()).thenReturn(Map.of());

    RangerResourceACLs rolesACLs = mock(RangerResourceACLs.class);
    when(rolesACLs.getUserACLs()).thenReturn(Map.of());
    when(rolesACLs.getGroupACLs()).thenReturn(Map.of());
    when(rolesACLs.getRoleACLs()).thenReturn(Map.of("metadata-consumer", allViewAccessResults));

    List<Permission> allowAllPermissions =
        List.of(
            new Permission().withOperation(MetadataOperation.DELETE).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.CREATE).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.VIEW_ALL).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_ALL).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_DESCRIPTION).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_DISPLAY_NAME).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_CUSTOM_FIELDS).withAccess(Permission.Access.ALLOW));

    List<Permission> allowViewPermissions =
        List.of(
            new Permission().withOperation(MetadataOperation.DELETE).withAccess(Permission.Access.DENY),
            new Permission().withOperation(MetadataOperation.CREATE).withAccess(Permission.Access.DENY),
            new Permission().withOperation(MetadataOperation.VIEW_ALL).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_ALL).withAccess(Permission.Access.DENY),
            new Permission().withOperation(MetadataOperation.EDIT_DESCRIPTION).withAccess(Permission.Access.DENY),
            new Permission().withOperation(MetadataOperation.EDIT_DISPLAY_NAME).withAccess(Permission.Access.DENY),
            new Permission().withOperation(MetadataOperation.EDIT_CUSTOM_FIELDS).withAccess(Permission.Access.DENY));

    List<Permission> allowAllButCreateDeletePermissions =
        List.of(
            new Permission().withOperation(MetadataOperation.DELETE).withAccess(Permission.Access.DENY),
            new Permission().withOperation(MetadataOperation.CREATE).withAccess(Permission.Access.DENY),
            new Permission().withOperation(MetadataOperation.VIEW_ALL).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_ALL).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_DESCRIPTION).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_DISPLAY_NAME).withAccess(Permission.Access.ALLOW),
            new Permission().withOperation(MetadataOperation.EDIT_CUSTOM_FIELDS).withAccess(Permission.Access.ALLOW));

    return Stream.of(
        Arguments.of(justAlice, aliceAllowAllACLs, allowAllPermissions),
        Arguments.of(justAlice, aliceAllowViewACLs, allowViewPermissions),
        Arguments.of(justAlice, aliceAllowViewAndAdminACLs, allowViewPermissions),
        Arguments.of(justAlice, publicAllowViewACLs, allowViewPermissions),
        Arguments.of(moderatorAlice, publicAndModeratorACLs, allowAllButCreateDeletePermissions),
        Arguments.of(consumerAlice, rolesACLs, allowViewPermissions));
  }
}
