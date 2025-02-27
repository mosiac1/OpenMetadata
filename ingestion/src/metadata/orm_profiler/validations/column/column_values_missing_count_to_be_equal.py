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
ColumnValuesMissingCount validation implementation
"""
# pylint: disable=duplicate-code
from datetime import datetime
from typing import Optional

from sqlalchemy import inspect
from sqlalchemy.orm import DeclarativeMeta

from metadata.generated.schema.entity.data.table import ColumnProfile
from metadata.generated.schema.tests.basic import TestCaseResult, TestCaseStatus
from metadata.generated.schema.tests.column.columnValuesMissingCountToBeEqual import (
    ColumnValuesMissingCount,
)
from metadata.orm_profiler.metrics.core import add_props
from metadata.orm_profiler.metrics.registry import Metrics
from metadata.orm_profiler.profiler.runner import QueryRunner
from metadata.utils.logger import profiler_logger

logger = profiler_logger()


def column_values_missing_count_to_be_equal(
    test_case: ColumnValuesMissingCount,
    col_profile: ColumnProfile,
    execution_date: datetime,
    runner: QueryRunner = None,
    table: Optional[DeclarativeMeta] = None,
) -> TestCaseResult:
    """
    Validate Column Values metric
    :param test_case: ColumnValuesMissingCount. Just used to trigger singledispatch
    :param col_profile: should contain count and distinct count metrics
    :param execution_date: Datetime when the tests ran
    :param session: SQLAlchemy Session, for tests that need to compute new metrics
    :param table: SQLAlchemy Table, for tests that need to compute new metrics
    :param profile_sample: % of the data to run the profiler on
    :return: TestCaseResult with status and results
    """

    if col_profile.nullCount is None:
        msg = "We expect `nullCount` to be informed on the profiler for ColumnValuesMissingCount."
        logger.error(msg)
        return TestCaseResult(
            timestamp=execution_date.timestamp(),
            testCaseStatus=TestCaseStatus.Aborted,
            result=msg,
        )

    missing_count = col_profile.nullCount
    if test_case.missingValueMatch:
        set_count = add_props(values=test_case.missingValueMatch)(
            Metrics.COUNT_IN_SET.value
        )

        try:
            col = next(
                (col for col in inspect(table).c if col.name == col_profile.name),
                None,
            )
            if col is None:
                raise ValueError(
                    f"Cannot find the configured column {col_profile.name} for ColumnValuesToBeNotInSet"
                )

            set_count_dict = dict(runner.select_first_from_sample(set_count(col).fn()))
            set_count_res = set_count_dict.get(Metrics.COUNT_IN_SET.name)

            # Add set count for special values into the missing count
            missing_count += set_count_res

        except Exception as err:  # pylint: disable=broad-except
            msg = f"Error computing {test_case.__class__.__name__} for {table.__tablename__}.{col_profile.name} - {err}"
            logger.error(msg)
            return TestCaseResult(
                timestamp=execution_date.timestamp(),
                testCaseStatus=TestCaseStatus.Aborted,
                result=msg,
            )

    status = (
        TestCaseStatus.Success
        if missing_count == test_case.missingCountValue
        else TestCaseStatus.Failed
    )
    result = f"Found missingCount={missing_count}. It should be {test_case.missingCountValue}."

    return TestCaseResult(
        timestamp=execution_date.timestamp(), testCaseStatus=status, result=result
    )
