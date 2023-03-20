/*
 *  Copyright 2022 Collate
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

import { CloseOutlined } from '@ant-design/icons';
import classNames from 'classnames';
import { isNil } from 'lodash';
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getEntityPermissionById } from '../../../axiosAPIs/permissionAPI';
import { NO_PERMISSION_TO_VIEW } from '../../../constants/HelperTextUtil';
import { ExplorePageTabs } from '../../../enums/Explore.enum';
import { Dashboard } from '../../../generated/entity/data/dashboard';
import { Mlmodel } from '../../../generated/entity/data/mlmodel';
import { Pipeline } from '../../../generated/entity/data/pipeline';
import { Table } from '../../../generated/entity/data/table';
import { Topic } from '../../../generated/entity/data/topic';
import { Access } from '../../../generated/entity/policies/accessControl/resourcePermission';
import { Operation } from '../../../generated/entity/policies/policy';
import { showErrorToast } from '../../../utils/ToastUtils';
import ErrorPlaceHolder from '../../common/error-with-placeholder/ErrorPlaceHolder';
import Loader from '../../Loader/Loader';
import { ResourceEntity } from '../../PermissionProvider/PermissionProvider.interface';
import DashboardSummary from './DashboardSummary/DashboardSummary.component';
import { EntitySummaryPanelProps } from './EntitySummaryPanel.interface';
import './EntitySummaryPanel.style.less';
import MlModelSummary from './MlModelSummary/MlModelSummary.component';
import PipelineSummary from './PipelineSummary/PipelineSummary.component';
import TableSummary from './TableSummary/TableSummary.component';
import TopicSummary from './TopicSummary/TopicSummary.component';

const exploreTabToResourceType: { [key in string]: ResourceEntity } = {
  [ExplorePageTabs.TABLES]: ResourceEntity.TABLE,
  [ExplorePageTabs.TOPICS]: ResourceEntity.TOPIC,
  [ExplorePageTabs.DASHBOARDS]: ResourceEntity.DASHBOARD,
  [ExplorePageTabs.MLMODELS]: ResourceEntity.ML_MODEL,
  [ExplorePageTabs.PIPELINES]: ResourceEntity.PIPELINE,
};

export default function EntitySummaryPanel({
  entityDetails,
  handleClosePanel,
}: EntitySummaryPanelProps) {
  const { tab } = useParams<{ tab: string }>();

  const [isLoading, setIsLoading] = useState(false);

  const [isPermission, setIsPermission] = useState(true);

  const [summaryComponent, setSummaryComponent] = useState<
    React.ReactElement | undefined
  >();

  const getSummaryComponent = () => {
    switch (entityDetails.entityType) {
      case ExplorePageTabs.TABLES:
        return <TableSummary entityDetails={entityDetails.details as Table} />;

      case ExplorePageTabs.TOPICS:
        return <TopicSummary entityDetails={entityDetails.details as Topic} />;

      case ExplorePageTabs.DASHBOARDS:
        return (
          <DashboardSummary
            entityDetails={entityDetails.details as Dashboard}
          />
        );

      case ExplorePageTabs.PIPELINES:
        return (
          <PipelineSummary entityDetails={entityDetails.details as Pipeline} />
        );

      case ExplorePageTabs.MLMODELS:
        return (
          <MlModelSummary entityDetails={entityDetails.details as Mlmodel} />
        );

      default:
        return undefined;
    }
  };

  useEffect(() => {
    if (isNil(entityDetails)) {
      return;
    }
    setIsLoading(true);
    getEntityPermissionById(
      exploreTabToResourceType[entityDetails.entityType],
      entityDetails.details.id
    )
      .then((perms) => {
        if (
          perms.permissions.find((p) => p.operation === Operation.ViewAll)
            ?.access === Access.Allow
        ) {
          setIsPermission(true);
          setSummaryComponent(getSummaryComponent());
        } else {
          setIsPermission(false);
        }
      })
      .catch((err) => {
        showErrorToast(err);
        setIsPermission(false);
      })
      .finally(() => setIsLoading(false));
  }, [tab, entityDetails]);

  return (
    <div className={classNames('summary-panel-container')}>
      {isLoading ? (
        <div className={classNames('m-md')}>
          <Loader />
        </div>
      ) : !isPermission ? (
        <div className={classNames('m-md')}>
          <ErrorPlaceHolder>{NO_PERMISSION_TO_VIEW}</ErrorPlaceHolder>
        </div>
      ) : (
        summaryComponent
      )}
      <CloseOutlined className="close-icon" onClick={handleClosePanel} />
    </div>
  );
}
