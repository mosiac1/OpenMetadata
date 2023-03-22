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
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.base.CaseFormat;
import com.google.common.collect.ImmutableMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.openmetadata.schema.EntityInterface;
import org.openmetadata.schema.api.services.CreateDashboardService;
import org.openmetadata.schema.api.services.CreateDatabaseService;
import org.openmetadata.schema.api.services.CreateMessagingService;
import org.openmetadata.schema.api.services.CreateMlModelService;
import org.openmetadata.schema.api.services.CreatePipelineService;
import org.openmetadata.schema.entity.data.Chart;
import org.openmetadata.schema.entity.data.Dashboard;
import org.openmetadata.schema.entity.data.Database;
import org.openmetadata.schema.entity.data.DatabaseSchema;
import org.openmetadata.schema.entity.data.Glossary;
import org.openmetadata.schema.entity.data.GlossaryTerm;
import org.openmetadata.schema.entity.data.Location;
import org.openmetadata.schema.entity.data.MlModel;
import org.openmetadata.schema.entity.data.Pipeline;
import org.openmetadata.schema.entity.data.Table;
import org.openmetadata.schema.entity.data.Topic;
import org.openmetadata.schema.entity.services.DashboardService;
import org.openmetadata.schema.entity.services.DatabaseService;
import org.openmetadata.schema.entity.services.MessagingService;
import org.openmetadata.schema.entity.services.MlModelService;
import org.openmetadata.schema.entity.services.PipelineService;
import org.openmetadata.schema.entity.services.StorageService;
import org.openmetadata.schema.tests.TestCase;
import org.openmetadata.schema.tests.TestSuite;
import org.openmetadata.schema.type.EntityReference;
import org.openmetadata.schema.type.StorageServiceType;
import org.openmetadata.schema.type.TagLabel;
import org.openmetadata.security.ResourceContextInterface;

public class RangerOpenmetadataAccessResourceTest {

  static {
    /*
    This static Map is initialized by org.openmetadata.service.Entity which is outside the scope of this module.
    For testing purposes, this mocks its functionality.
     */
    Stream.of(
            DatabaseService.class,
            Database.class,
            DatabaseSchema.class,
            Table.class,
            Dashboard.class,
            DashboardService.class,
            Chart.class,
            MessagingService.class,
            Topic.class,
            StorageService.class,
            Location.class,
            Glossary.class,
            GlossaryTerm.class,
            TestSuite.class,
            TestCase.class,
            PipelineService.class,
            Pipeline.class)
        .map(Class::getSimpleName)
        .forEach(
            className ->
                EntityInterface.CANONICAL_ENTITY_NAME_MAP.put(
                    className.toLowerCase(Locale.ROOT), CaseFormat.UPPER_CAMEL.to(CaseFormat.LOWER_CAMEL, className)));
    // MLModel is a special case
    EntityInterface.CANONICAL_ENTITY_NAME_MAP.put("mlmodel", "mlmodel");
    EntityInterface.CANONICAL_ENTITY_NAME_MAP.put("mlmodelservice", "mlmodel_service");
  }

  private static final DatabaseService DATABASE_SERVICE =
      new DatabaseService()
          .withId(UUID.randomUUID())
          .withName("test_database_service_name")
          .withServiceType(CreateDatabaseService.DatabaseServiceType.Snowflake);

  private static final Database DATABASE =
      new Database()
          .withId(UUID.randomUUID())
          .withName("test_database_name")
          .withService(DATABASE_SERVICE.getEntityReference());

  private static final DatabaseSchema DATABASE_SCHEMA =
      new DatabaseSchema()
          .withId(UUID.randomUUID())
          .withName("test_database_schema_name")
          .withDatabase(DATABASE.getEntityReference())
          .withService(DATABASE_SERVICE.getEntityReference());

  private static final Table TABLE =
      new Table()
          .withId(UUID.randomUUID())
          .withName("test_table_name")
          .withDatabaseSchema(DATABASE_SCHEMA.getEntityReference())
          .withDatabase(DATABASE.getEntityReference())
          .withService(DATABASE_SERVICE.getEntityReference());

  private static final MlModelService MLMODEL_SERVICE =
      new MlModelService()
          .withId(UUID.randomUUID())
          .withName("test_mlmodel_service_name")
          .withServiceType(CreateMlModelService.MlModelServiceType.Mlflow);

  private static final MlModel MLMODEL =
      new MlModel()
          .withId(UUID.randomUUID())
          .withName("test_mlmodel_name")
          .withService(MLMODEL_SERVICE.getEntityReference());

  private static final DashboardService DASHBOARD_SERVICE =
      new DashboardService()
          .withId(UUID.randomUUID())
          .withName("test_dashboard_service_name")
          .withServiceType(CreateDashboardService.DashboardServiceType.Superset);

  private static final Dashboard DASHBOARD =
      new Dashboard()
          .withId(UUID.randomUUID())
          .withName("test_dashboard_name")
          .withService(DASHBOARD_SERVICE.getEntityReference());

  private static final Chart CHART =
      new Chart()
          .withId(UUID.randomUUID())
          .withName("test_chart_name")
          .withService(DASHBOARD_SERVICE.getEntityReference());

  private static final MessagingService MESSAGING_SERVICE =
      new MessagingService()
          .withId(UUID.randomUUID())
          .withName("test_messaging_service_name")
          .withServiceType(CreateMessagingService.MessagingServiceType.Kafka);

  private static final Topic TOPIC =
      new Topic()
          .withId(UUID.randomUUID())
          .withName("test_topic_name")
          .withService(MESSAGING_SERVICE.getEntityReference());

  private static final StorageService STORAGE_SERVICE =
      new StorageService()
          .withId(UUID.randomUUID())
          .withName("test_storage_service_name")
          .withServiceType(StorageServiceType.S3);

  private static final Location LOCATION =
      new Location()
          .withId(UUID.randomUUID())
          .withName("test_location_name")
          .withService(STORAGE_SERVICE.getEntityReference());

  private static final Glossary GLOSSARY = new Glossary().withId(UUID.randomUUID()).withName("test_glossary_name");

  private static final GlossaryTerm GLOSSARY_TERM =
      new GlossaryTerm()
          .withId(UUID.randomUUID())
          .withName("test_glossary_term_name")
          .withGlossary(GLOSSARY.getEntityReference());

  private static final TestSuite TEST_SUITE =
      new TestSuite().withId(UUID.randomUUID()).withName("test_test_suite_name");

  private static final TestCase TEST_CASE =
      new TestCase()
          .withId(UUID.randomUUID())
          .withName("test_test_case_name")
          .withTestSuite(TEST_SUITE.getEntityReference());

  private static final PipelineService PIPELINE_SERVICE =
      new PipelineService()
          .withId(UUID.randomUUID())
          .withName("test_pipeline_service_name")
          .withServiceType(CreatePipelineService.PipelineServiceType.Airflow);

  private static final Pipeline PIPELINE =
      new Pipeline()
          .withId(UUID.randomUUID())
          .withName("test_pipeline_name")
          .withService(PIPELINE_SERVICE.getEntityReference());

  @ParameterizedTest
  @CsvSource({
    "bot,bot",
    "chart,chart",
    "dashboard,dashboard",
    "dashboardService,dashboard_service",
    "databaseSchema,database_schema",
    "mlmodel,mlmodel",
    "mlmodelService,mlmodel_service",
    "webAnalyticalEvent,web_analytical_event",
    "dataInsightChart,data_insight_chart"
  })
  public void testConstructorWithStringSetsValue(String openMetadataResource, String rangerResource) {
    RangerOpenmetadataAccessResource resource = new RangerOpenmetadataAccessResource(openMetadataResource);
    assertTrue(resource.exists(rangerResource));
    assertEquals(resource.getValue(rangerResource), "*");
  }

  @ParameterizedTest
  @MethodSource("provideEntitiesAndTestValues")
  public void testConstructorWithResourceContextSetsValues(EntityInterface entity, Map<String, Object> expectedValues) {
    RangerOpenmetadataAccessResource resource = new RangerOpenmetadataAccessResource(new TestResourceContext(entity));
    for (Map.Entry<String, Object> entry : expectedValues.entrySet()) {
      assertTrue(resource.exists(entry.getKey()));
      assertEquals(resource.getValue(entry.getKey()), entry.getValue());
    }
  }

  private static Stream<Arguments> provideEntitiesAndTestValues() {
    Map<String, Object> databaseServiceTestValues = Map.of("database_service", "test_database_service_name");
    Map<String, Object> databaseTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(databaseServiceTestValues)
            .put("database", "test_database_name")
            .build();
    Map<String, Object> databaseSchemaTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(databaseTestValues)
            .put("database_schema", "test_database_schema_name")
            .build();
    Map<String, Object> tableTestValue =
        ImmutableMap.<String, Object>builder()
            .putAll(databaseTestValues)
            .put("database_schema", "test_database_schema_name")
            .build();

    Map<String, Object> mlmodelServiceTestValues = Map.of("mlmodel_service", "test_mlmodel_service_name");
    Map<String, Object> mlmodelTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(mlmodelServiceTestValues)
            .put("mlmodel", "test_mlmodel_name")
            .build();

    Map<String, Object> dashboardServiceTestValues = Map.of("dashboard_service", "test_dashboard_service_name");
    Map<String, Object> dashboardTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(dashboardServiceTestValues)
            .put("dashboard", "test_dashboard_name")
            .build();
    Map<String, Object> chartTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(dashboardServiceTestValues)
            .put("chart", "test_chart_name")
            .build();

    Map<String, Object> messagingServiceTestValues = Map.of("messaging_service", "test_messaging_service_name");
    Map<String, Object> topicTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(messagingServiceTestValues)
            .put("topic", "test_topic_name")
            .build();

    Map<String, Object> storageServiceTestValues = Map.of("storage_service", "test_storage_service_name");
    Map<String, Object> locationTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(storageServiceTestValues)
            .put("location", "test_location_name")
            .build();

    Map<String, Object> glossaryTestValues = Map.of("glossary", "test_glossary_name");
    Map<String, Object> glossaryTermTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(glossaryTestValues)
            .put("glossary_term", "test_glossary_term_name")
            .build();

    Map<String, Object> testSuiteTestValues = Map.of("test_suite", "test_test_suite_name");
    Map<String, Object> testCaseTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(testSuiteTestValues)
            .put("test_case", "test_test_case_name")
            .build();

    Map<String, Object> pipelineServiceTestValues = Map.of("pipeline_service", "test_pipeline_service_name");
    Map<String, Object> pipelineTestValues =
        ImmutableMap.<String, Object>builder()
            .putAll(pipelineServiceTestValues)
            .put("pipeline", "test_pipeline_name")
            .build();

    Table tableAllNull = new Table().withId(UUID.randomUUID()).withName("test_table_with_missing_sub_values");
    Map<String, Object> tableAllNullTestValues =
        Map.of(
            "table",
            "test_table_with_missing_sub_values",
            "database_service",
            "*",
            "database",
            "*",
            "database_schema",
            "*");

    Table tableWithDatabaseService =
        new Table()
            .withId(UUID.randomUUID())
            .withName("test_table_with_missing_sub_values")
            .withService(DATABASE_SERVICE.getEntityReference());
    Map<String, Object> tableWithDatabaseServiceTestValues =
        Map.of(
            "table",
            "test_table_with_missing_sub_values",
            "database_service",
            "test_database_service_name",
            "database",
            "*",
            "database_schema",
            "*");

    MlModel mlmodelAllNull = new MlModel().withId(UUID.randomUUID()).withName("test_mlmodel_with_missing_sub_values");
    Map<String, Object> mlmodelAllNullTestValues =
        Map.of("mlmodel", "test_mlmodel_with_missing_sub_values", "mlmodel_service", "*");

    return Stream.of(
        Arguments.of(DATABASE_SERVICE, databaseServiceTestValues),
        Arguments.of(DATABASE, databaseTestValues),
        Arguments.of(DATABASE_SCHEMA, databaseSchemaTestValues),
        Arguments.of(TABLE, tableTestValue),
        Arguments.of(MLMODEL_SERVICE, mlmodelServiceTestValues),
        Arguments.of(MLMODEL, mlmodelTestValues),
        Arguments.of(DASHBOARD_SERVICE, dashboardServiceTestValues),
        Arguments.of(DASHBOARD, dashboardTestValues),
        Arguments.of(CHART, chartTestValues),
        Arguments.of(MESSAGING_SERVICE, messagingServiceTestValues),
        Arguments.of(TOPIC, topicTestValues),
        Arguments.of(STORAGE_SERVICE, storageServiceTestValues),
        Arguments.of(LOCATION, locationTestValues),
        Arguments.of(GLOSSARY, glossaryTestValues),
        Arguments.of(GLOSSARY_TERM, glossaryTermTestValues),
        Arguments.of(TEST_SUITE, testSuiteTestValues),
        Arguments.of(TEST_CASE, testCaseTestValues),
        Arguments.of(PIPELINE_SERVICE, pipelineServiceTestValues),
        Arguments.of(PIPELINE, pipelineTestValues),
        Arguments.of(tableAllNull, tableAllNullTestValues),
        Arguments.of(tableWithDatabaseService, tableWithDatabaseServiceTestValues),
        Arguments.of(mlmodelAllNull, mlmodelAllNullTestValues));
  }

  private static final class TestResourceContext implements ResourceContextInterface {

    private final EntityInterface entity;

    public TestResourceContext(EntityInterface entityInterface) {
      this.entity = entityInterface;
    }

    @Override
    public String getResource() {
      return entity.getEntityReference().getType();
    }

    @Override
    public EntityReference getOwner() {
      return entity.getOwner();
    }

    @Override
    public List<TagLabel> getTags() {
      return entity.getTags();
    }

    @Override
    public EntityInterface getEntity() {
      return entity;
    }
  }
}
