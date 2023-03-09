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

import com.google.common.base.CaseFormat;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Locale;
import java.util.Optional;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.openmetadata.schema.EntityInterface;
import org.openmetadata.schema.entity.data.*;
import org.openmetadata.schema.entity.services.DashboardService;
import org.openmetadata.schema.entity.services.DatabaseService;
import org.openmetadata.schema.entity.services.MessagingService;
import org.openmetadata.schema.entity.services.MlModelService;
import org.openmetadata.schema.entity.services.PipelineService;
import org.openmetadata.schema.entity.services.StorageService;
import org.openmetadata.schema.entity.tags.Tag;
import org.openmetadata.schema.tests.TestCase;
import org.openmetadata.schema.tests.TestSuite;
import org.openmetadata.schema.type.EntityReference;
import org.openmetadata.security.ResourceContextInterface;

public class RangerOpenmetadataAccessResource extends RangerAccessResourceImpl {

  @Getter private final String openMetadataResourceName;

  @Getter private final String rangerResourceName;

  public RangerOpenmetadataAccessResource(String openMetadataResourceName) {
    this.openMetadataResourceName = openMetadataResourceName;
    this.rangerResourceName = formatOpenMetadataResourceToRanger(openMetadataResourceName);

    setValue(rangerResourceName, "*");
  }

  public RangerOpenmetadataAccessResource(RangerServiceDef.RangerResourceDef rangerResourceDef) {
    this.rangerResourceName = rangerResourceDef.getName();
    this.openMetadataResourceName = formatRangerResourceToOpenMetadata(rangerResourceName);

    setValue(rangerResourceName, "*");
  }

  @SneakyThrows
  public RangerOpenmetadataAccessResource(ResourceContextInterface resourceContextInterface) {

    openMetadataResourceName = resourceContextInterface.getResource();
    rangerResourceName = formatOpenMetadataResourceToRanger(resourceContextInterface.getResource());

    Optional<EntityInterface> entityInterfaceOpt = Optional.ofNullable(resourceContextInterface.getEntity());

    if (entityInterfaceOpt.isPresent()) {
      // We can get the full Entity from the DAO
      EntityInterface entity = entityInterfaceOpt.get();

      setValue(entity.getEntityReference());

      Class<? extends EntityInterface> entityClazz = entity.getClass();

      try {
        Method method = this.getClass().getDeclaredMethod("setSubValues", entityClazz);
        method.invoke(this, entity);
      } catch (NoSuchMethodException ignored) {
      } catch (InvocationTargetException | IllegalAccessException e) {
        throw new RuntimeException(
            String.format("Failed to call RangerOpenmetadataAccessResource#setSubValue method for entity %s", entity),
            e);
      }
    } else {
      // We can't get the full entity
      setValue(rangerResourceName, "*");
    }
  }

  // Column, Table, Database, DatabaseSchema setSubValues
  private void setSubValues(Database database) {
    setValue(database.getService(), DatabaseService.class);
  }

  private void setSubValues(DatabaseSchema databaseSchema) {
    setValue(databaseSchema.getService(), DatabaseService.class);
    setValue(databaseSchema.getDatabase(), Database.class);
  }

  private void setSubValues(Table table) {
    setValue(table.getService(), DatabaseService.class);
    setValue(table.getDatabase(), Database.class);
    setValue(table.getDatabaseSchema(), DatabaseSchema.class);
  }

  private void setSubValues(MlModel mlmodel) {
    setValue(mlmodel.getService(), MlModelService.class);
  }

  private void setSubValues(Dashboard dashboard) {
    setValue(dashboard.getService(), DashboardService.class);
  }

  private void setSubValues(Chart chart) {
    setValue(chart.getService(), DashboardService.class);
  }

  private void setSubValues(Topic topic) {
    setValue(topic.getService(), MessagingService.class);
  }

  private void setSubValues(Location location) {
    setValue(location.getService(), StorageService.class);
  }

  private void setSubValues(GlossaryTerm glossaryTerm) {
    setValue(glossaryTerm.getGlossary(), Glossary.class);
  }

  private void setSubValues(TestCase testCase) {
    setValue(testCase.getTestSuite(), TestSuite.class);
  }

  private void setSubValue(Tag tag) {
    // TODO: Tags don't have a pointer back to their parent TagCategory, this needs to be fixed
    // This is fixed in version 0.13.2 so will no handle it here
  }

  private void setSubValues(Pipeline pipeline) {
    setValue(pipeline.getService(), PipelineService.class);
  }

  private void setValue(EntityReference entityReference, Class<? extends EntityInterface> clazz) {
    if (entityReference == null) {
      setValue(formatOpenMetadataClassNameToRangerResource(clazz), "*");
    } else {
      setValue(entityReference);
    }
  }

  private void setValue(EntityReference entityReference) {
    setValue(getRangerResourceName(entityReference), entityReference.getName());
  }

  private static String getRangerResourceName(EntityReference entityReference) {
    return formatOpenMetadataResourceToRanger(entityReference.getType());
  }

  private static String formatOpenMetadataResourceToRanger(String openMetadataResourceName) {
    return CaseFormat.LOWER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, openMetadataResourceName);
  }

  private static String formatRangerResourceToOpenMetadata(String rangerResourceName) {
    return CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.LOWER_CAMEL, rangerResourceName);
  }

  private static String formatOpenMetadataClassNameToRangerResource(Class<? extends EntityInterface> clazz) {
    return formatOpenMetadataResourceToRanger(
        EntityInterface.CANONICAL_ENTITY_NAME_MAP.get(clazz.getSimpleName().toLowerCase(Locale.ROOT)));
  }
}
