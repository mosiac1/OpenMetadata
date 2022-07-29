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

import { AxiosError } from 'axios';
import { isEmpty } from 'lodash';
import { FilterObject } from 'Models';
import React, {
  Fragment,
  FunctionComponent,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useHistory, useLocation, useParams } from 'react-router-dom';
import AppState from '../../AppState';
import PageContainerV1 from '../../components/containers/PageContainerV1';
import Explore from '../../components/Explore/Explore.component';
import { UrlParams } from '../../components/Explore/explore.interface';
import { getExplorePathWithSearch, PAGE_SIZE } from '../../constants/constants';
import {
  getCurrentIndex,
  getCurrentTab,
  getInitialFilter,
  getQueryParam,
  getSearchFilter,
  INITIAL_FROM,
  INITIAL_SORT_ORDER,
  tabsInfo,
} from '../../constants/explore.constants';
import { SearchIndex } from '../../enums/search.enum';
import jsonData from '../../jsons/en';
import { getTotalEntityCountByType } from '../../utils/EntityUtils';
import { prepareQueryParams } from '../../utils/FilterUtils';
import { showErrorToast } from '../../utils/ToastUtils';
import {
  ExploreSearchSource,
  SearchRequest,
  SearchResponse,
  SearchSource,
} from '../../interface/search.interface';
import { getPostFilter, searchQuery } from '../../axiosAPIs/searchAPI';

const ExplorePage: FunctionComponent = () => {
  const location = useLocation();
  const history = useHistory();
  const initialFilter = useMemo(
    () => getQueryParam(getInitialFilter(location.search)),
    [location.search]
  );
  const searchFilter = useMemo(
    () => getQueryParam(getSearchFilter(location.search)),
    [location.search]
  );
  const { searchQuery: searchQueryParam, tab } = useParams<UrlParams>();
  const [searchText, setSearchText] = useState<string>(searchQueryParam || '');
  const [tableCount, setTableCount] = useState<number>(0);
  const [topicCount, setTopicCount] = useState<number>(0);
  const [dashboardCount, setDashboardCount] = useState<number>(0);
  const [pipelineCount, setPipelineCount] = useState<number>(0);
  const [dbtModelCount, setDbtModelCount] = useState<number>(0);
  const [mlModelCount, setMlModelCount] = useState<number>(0);
  const [searchResult, setSearchResult] =
    useState<SearchResponse<ExploreSearchSource>>();
  const [showDeleted, setShowDeleted] = useState(false);
  const [initialSortField] = useState<string>(
    tabsInfo[getCurrentTab(tab) - 1].sortField
  );

  const handleSearchText = (text: string) => {
    setSearchText(text);
  };

  const handleTableCount = (count: number) => {
    setTableCount(count);
  };

  const handleTopicCount = (count: number) => {
    setTopicCount(count);
  };

  const handleDashboardCount = (count: number) => {
    setDashboardCount(count);
  };

  const handlePipelineCount = (count: number) => {
    setPipelineCount(count);
  };

  const handleDbtModelCount = (count: number) => {
    setDbtModelCount(count);
  };

  const handleMlModelCount = (count: number) => {
    setMlModelCount(count);
  };

  const handlePathChange = (path: string) => {
    AppState.updateExplorePageTab(path);
  };

  /**
   * on filter change , change the route
   * @param filterData - filter object
   */
  const handleFilterChange = (filterData: FilterObject) => {
    const params = prepareQueryParams(filterData, initialFilter);

    const explorePath = getExplorePathWithSearch(searchQueryParam, tab);

    history.push({
      pathname: explorePath,
      search: params,
    });
  };

  const fetchCounts = () => {
    const entities = [
      SearchIndex.TABLE,
      SearchIndex.TOPIC,
      SearchIndex.DASHBOARD,
      SearchIndex.PIPELINE,
      SearchIndex.MLMODEL,
    ];

    const entityCounts = entities.map((entity) =>
      searchQuery({
        query: searchText,
        from: 0,
        size: 0,
        postFilter: getPostFilter(initialFilter),
        searchIndex: entity,
        includeDeleted: showDeleted,
        trackTotalHits: true,
      })
    );

    Promise.allSettled(entityCounts)
      .then(
        ([table, topic, dashboard, pipeline, mlmodel]: PromiseSettledResult<
          SearchResponse<SearchSource>
        >[]) => {
          setTableCount(
            table.status === 'fulfilled'
              ? getTotalEntityCountByType(
                  table.value.aggregations?.['sterms#EntityType']?.buckets
                )
              : 0
          );
          setTopicCount(
            topic.status === 'fulfilled'
              ? getTotalEntityCountByType(
                  topic.value.aggregations?.['sterms#EntityType']?.buckets
                )
              : 0
          );
          setDashboardCount(
            dashboard.status === 'fulfilled'
              ? getTotalEntityCountByType(
                  dashboard.value.aggregations?.['sterms#EntityType']?.buckets
                )
              : 0
          );
          setPipelineCount(
            pipeline.status === 'fulfilled'
              ? getTotalEntityCountByType(
                  pipeline.value.aggregations?.['sterms#EntityType']?.buckets
                )
              : 0
          );
          setMlModelCount(
            mlmodel.status === 'fulfilled'
              ? getTotalEntityCountByType(
                  mlmodel.value.aggregations?.['sterms#EntityType']?.buckets
                )
              : 0
          );
        }
      )
      .catch((err: AxiosError) => {
        showErrorToast(
          err,
          jsonData['api-error-messages']['fetch-entity-count-error']
        );
      });
  };

  const fetchData = (req: SearchRequest) =>
    searchQuery(req).then((res) =>
      setSearchResult(res as SearchResponse<ExploreSearchSource>)
    );

  useEffect(() => {
    fetchCounts();
  }, [searchText, showDeleted, initialFilter]);

  useEffect(() => {
    AppState.updateExplorePageTab(tab);
  }, [tab]);

  useEffect(() => {
    setSearchResult(undefined);
    fetchData({
      query: searchText,
      from: INITIAL_FROM,
      size: PAGE_SIZE,
      postFilter: getPostFilter(initialFilter),
      sortField: initialSortField,
      sortOrder: INITIAL_SORT_ORDER,
      searchIndex: getCurrentIndex(tab),
    });
    // {
    //   query: searchText,
    //   from: INITIAL_FROM,
    //   size: ZERO_SIZE,
    //   filters: getFilterString(initialFilter),
    //   sortField: initialSortField,
    //   sortOrder: INITIAL_SORT_ORDER,
    //   searchIndex: getCurrentIndex(tab),
    // },
    // {
    //   query: searchText,
    //   from: INITIAL_FROM,
    //   size: ZERO_SIZE,
    //   filters: getFilterString(initialFilter),
    //   sortField: initialSortField,
    //   sortOrder: INITIAL_SORT_ORDER,
    //   searchIndex: getCurrentIndex(tab),
    // },
    // {
    //   query: searchText,
    //   from: INITIAL_FROM,
    //   size: ZERO_SIZE,
    //   filters: getFilterString(initialFilter),
    //   sortField: initialSortField,
    //   sortOrder: INITIAL_SORT_ORDER,
    //   searchIndex: getCurrentIndex(tab),
    // },
  }, []);

  return (
    <Fragment>
      <PageContainerV1>
        <Explore
          fetchCount={fetchCounts}
          fetchData={fetchData}
          handleFilterChange={handleFilterChange}
          handlePathChange={handlePathChange}
          handleSearchText={handleSearchText}
          initialFilter={initialFilter}
          isFilterSelected={!isEmpty(searchFilter) || !isEmpty(initialFilter)}
          searchFilter={searchFilter}
          searchQuery={searchQueryParam}
          searchResult={searchResult}
          searchText={searchText}
          showDeleted={showDeleted}
          sortValue={initialSortField}
          tab={tab}
          tabCounts={{
            table: tableCount,
            topic: topicCount,
            dashboard: dashboardCount,
            pipeline: pipelineCount,
            dbtModel: dbtModelCount,
            mlModel: mlModelCount,
          }}
          updateDashboardCount={handleDashboardCount}
          updateDbtModelCount={handleDbtModelCount}
          updateMlModelCount={handleMlModelCount}
          updatePipelineCount={handlePipelineCount}
          updateTableCount={handleTableCount}
          updateTopicCount={handleTopicCount}
          onShowDeleted={(checked) => setShowDeleted(checked)}
        />
      </PageContainerV1>
    </Fragment>
  );
};

export default ExplorePage;
