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

import { FilterObject } from 'Models';
import * as QueryBuilder from 'react-awesome-query-builder';
import {
  ExploreSearchSource,
  SearchRequest,
  SearchResponse,
  SearchSource,
} from '../../interface/search.interface';

export type UrlParams = {
  searchQuery: string;
  tab: string;
};

export type ExploreSearchData = {
  resSearchResults: SearchResponse<SearchSource>;
  resAggServiceType: SearchResponse<SearchSource>;
  resAggTier: SearchResponse<SearchSource>;
  resAggTag: SearchResponse<SearchSource>;
  resAggDatabase: SearchResponse<SearchSource>;
  resAggDatabaseSchema: SearchResponse<SearchSource>;
  resAggServiceName: SearchResponse<SearchSource>;
};

export interface ExploreProps {
  tabCounts: {
    table: number;
    topic: number;
    dashboard: number;
    pipeline: number;
    dbtModel: number;
    mlModel: number;
  };
  searchText: string;
  initialFilter?: FilterObject;
  searchFilter?: FilterObject;
  sortValue: string;
  tab: string;
  searchQuery: string;
  showDeleted: boolean;
  searchResult: SearchResponse<ExploreSearchSource> | undefined;
  isFilterSelected: boolean;
  fetchCount: () => void;
  handleFilterChange: (data: FilterObject) => void;
  handlePathChange: (path: string) => void;
  handleSearchText: (text: string) => void;
  updateTableCount: (count: number) => void;
  updateTopicCount: (count: number) => void;
  updateDashboardCount: (count: number) => void;
  updatePipelineCount: (count: number) => void;
  updateDbtModelCount: (count: number) => void;
  updateMlModelCount: (count: number) => void;
  fetchData: (req: SearchRequest) => void;
  onShowDeleted: (checked: boolean) => void;
}

export interface QueryBuilderState {
  config: QueryBuilder.Config;
  tree: QueryBuilder.ImmutableTree;
}
