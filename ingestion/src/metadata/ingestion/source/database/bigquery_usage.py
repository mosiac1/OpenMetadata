#  Copyright 2021 Collate
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""
Handle big query usage extraction
"""
from datetime import datetime

from google import auth

from metadata.generated.schema.entity.services.connections.database.bigQueryConnection import (
    BigQueryConnection,
)
from metadata.generated.schema.entity.services.connections.metadata.openMetadataConnection import (
    OpenMetadataConnection,
)
from metadata.generated.schema.entity.services.databaseService import (
    DatabaseServiceType,
)
from metadata.generated.schema.metadataIngestion.workflow import (
    Source as WorkflowSource,
)
from metadata.ingestion.api.source import InvalidSourceException
from metadata.ingestion.source.database.usage_source import UsageSource
from metadata.utils.logger import ingestion_logger
from metadata.utils.sql_queries import BIGQUERY_USAGE_STATEMENT

logger = ingestion_logger()


class BigqueryUsageSource(UsageSource):
    SERVICE_TYPE = DatabaseServiceType.BigQuery.value
    scheme = "bigquery"

    def __init__(self, config: WorkflowSource, metadata_config: OpenMetadataConnection):
        super().__init__(config, metadata_config)

        self.project_id = self.set_project_id()
        self.database = self.project_id

        self.sql_stmt = BIGQUERY_USAGE_STATEMENT

    @classmethod
    def create(cls, config_dict, metadata_config: OpenMetadataConnection):
        config: WorkflowSource = WorkflowSource.parse_obj(config_dict)
        connection: BigQueryConnection = config.serviceConnection.__root__.config
        if not isinstance(connection, BigQueryConnection):
            raise InvalidSourceException(
                f"Expected BigQueryConnection, but got {connection}"
            )
        return cls(config, metadata_config)

    def get_sql_statement(self, start_time: datetime, end_time: datetime) -> str:
        """
        returns sql statement to fetch query logs
        """
        return self.sql_stmt.format(
            start_time=start_time,
            end_time=end_time,
            region=self.connection.usageLocation,
        )

    @staticmethod
    def set_project_id():
        _, project_id = auth.default()
        return project_id
