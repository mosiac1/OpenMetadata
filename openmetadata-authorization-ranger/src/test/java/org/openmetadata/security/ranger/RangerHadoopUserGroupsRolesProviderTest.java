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
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Set;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openmetadata.security.SecurityContextInterface;

@ExtendWith(MockitoExtension.class)
public class RangerHadoopUserGroupsRolesProviderTest {

  private MockedStatic<UserGroupInformation> ugiMock;

  @Mock private RangerBasePlugin pluginMock;

  @Mock private UserGroupInformation bobUserMock;

  @Mock private UserGroupInformation aliceUserMock;

  @BeforeEach
  public void setUp() {
    ugiMock = mockStatic(UserGroupInformation.class);
  }

  @AfterEach
  public void tearDown() {
    ugiMock.close();
  }

  @Test
  public void testGetUserGroupsRolesFromSecurityContext() {

    // Given
    RangerHadoopUserGroupsRolesProvider groupsRolesProvider = new RangerHadoopUserGroupsRolesProvider(pluginMock);

    when(bobUserMock.getShortUserName()).thenReturn("bob");
    when(bobUserMock.getGroupNames()).thenReturn(new String[] {"group1", "group2"});
    when(pluginMock.getRolesFromUserAndGroups("bob", Set.of("group1", "group2"))).thenReturn(Set.of("role1", "role2"));

    ugiMock.when(UserGroupInformation::isInitialized).thenReturn(true);
    ugiMock.when(() -> UserGroupInformation.createRemoteUser("bob")).thenReturn(bobUserMock);

    // When
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(new TestSecurityContext("bob"));

    // Then
    assertEquals(ugr, new RangerUserGroupsRoles("bob", Set.of("group1", "group2"), Set.of("role1", "role2")));
    verify(pluginMock).getRolesFromUserAndGroups("bob", Set.of("group1", "group2"));
    verify(bobUserMock).getShortUserName();
    verify(bobUserMock).getGroupNames();
    ugiMock.verify(UserGroupInformation::isInitialized, times(1));
  }

  @Test
  public void testGetUserGroupsRolesWithOverride() {
    // Given
    RangerHadoopUserGroupsRolesProvider groupsRolesProvider = new RangerHadoopUserGroupsRolesProvider(pluginMock);

    when(aliceUserMock.getShortUserName()).thenReturn("alice");
    when(aliceUserMock.getGroupNames()).thenReturn(new String[] {"group3"});
    when(pluginMock.getRolesFromUserAndGroups("alice", Set.of("group3"))).thenReturn(Set.of("role3"));
    ugiMock.when(() -> UserGroupInformation.createRemoteUser("alice")).thenReturn(aliceUserMock);

    ugiMock.when(UserGroupInformation::isInitialized).thenReturn(true);

    // When
    RangerUserGroupsRoles ugr = groupsRolesProvider.getUserGroupsRoles(new TestSecurityContext("bob"), "alice");

    // Then
    assertEquals(ugr, new RangerUserGroupsRoles("alice", Set.of("group3"), Set.of("role3")));

    verify(pluginMock).getRolesFromUserAndGroups("alice", Set.of("group3"));
    verify(pluginMock, never()).getRolesFromUserAndGroups(eq("bob"), anySet());

    verify(aliceUserMock).getShortUserName();
    verify(aliceUserMock).getGroupNames();
    verify(bobUserMock, never()).getShortUserName();
    verify(bobUserMock, never()).getGroupNames();

    ugiMock.verify(UserGroupInformation::isInitialized);
  }

  @Test
  public void testUserGroupInformationUninitializedThrows() {
    // Given
    RangerHadoopUserGroupsRolesProvider groupsRolesProvider = new RangerHadoopUserGroupsRolesProvider(pluginMock);
    ugiMock.when(UserGroupInformation::isInitialized).thenReturn(false);

    // Then
    assertThrows(
        RuntimeException.class,
        () -> {
          // When
          groupsRolesProvider.getUserGroupsRoles(new TestSecurityContext("bob"));
        });
  }

  private static final class TestSecurityContext implements SecurityContextInterface {
    private final String user;

    private TestSecurityContext(String user) {
      this.user = user;
    }

    @Override
    public Principal getUserPrincipal() {
      return () -> user;
    }
  }
}
