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

import PropTypes from 'prop-types';
import React, { ReactNode } from 'react';
import { PAGE_SIZE } from '../../constants/constants';
import { MAX_RESULT_HITS } from '../../constants/explore.constants';
import { Paging } from '../../generated/type/paging';
import { pluralize } from '../../utils/CommonUtils';
import ErrorPlaceHolderES from '../common/error-with-placeholder/ErrorPlaceHolderES';
import NextPrevious from '../common/next-previous/NextPrevious';
import TableDataCard from '../common/table-data-card/TableDataCard';
import Loader from '../Loader/Loader';
import Onboarding from '../onboarding/Onboarding';
import {
  ExploreSearchSource,
  SearchHit,
} from '../../interface/search.interface';
import { SearchIndex } from '../../enums/search.enum';

export interface SearchedDataProp {
  children?: ReactNode;
  data: SearchHit<ExploreSearchSource>[];
  currentPage: number;
  isLoading?: boolean;
  paginate: (value: string | number) => void;
  totalValue: number;
  fetchLeftPanel?: () => ReactNode;
  showResultCount?: boolean;
  searchText?: string;
  showOnboardingTemplate?: boolean;
  showOnlyChildren?: boolean;
  isFilterSelected: boolean;
}

const SearchedData: React.FC<SearchedDataProp> = ({
  children,
  data,
  currentPage,
  isLoading = false,
  paginate,
  showResultCount = false,
  showOnboardingTemplate = false,
  showOnlyChildren = false,
  searchText,
  totalValue,
  isFilterSelected,
}: SearchedDataProp) => {
  const highlightSearchResult = () => {
    return data.map(({ _index, _source, highlight }, idx) => {
      let { description, name } = _source;

      const highLightedTexts = highlight?.description ?? [];

      if (highLightedTexts.length > 0) {
        const matchTextArr = highLightedTexts.map((val) =>
          val.replace(/<\/?span(.*?)>/g, '')
        );

        matchTextArr.forEach((text, i) => {
          description = description?.replace(text, highLightedTexts[i]);
        });
      }

      if (highlight) {
        name = highlight?.name?.join(' ') ?? name;
      }

      const matches = highlight
        ? Object.entries(highlight).map(([key, value]) => {
            let highlightedTextCount = 0;
            value.forEach((value) => {
              const currentCount = value.match(
                /<span(.*?)>(.*?)<\/span>/g
              )?.length;

              highlightedTextCount = highlightedTextCount + (currentCount || 0);
            });

            return {
              key,
              value: highlightedTextCount,
            };
          })
        : // .filter((d) => !ASSETS_NAME.includes(d.key))
          [];

      return (
        <div className="tw-mb-3" key={idx}>
          <TableDataCard
            id={`tabledatacard${idx}`}
            matches={matches}
            searchIndex={_index as SearchIndex}
            source={{ ..._source, name, description }}
          />
        </div>
      );
    });
  };

  const ResultCount = () => {
    if (showResultCount && (isFilterSelected || searchText)) {
      if (MAX_RESULT_HITS === totalValue) {
        return <div className="tw-mb-1">{`About ${totalValue} results`}</div>;
      } else {
        return <div className="tw-mb-1">{pluralize(totalValue, 'result')}</div>;
      }
    } else {
      return null;
    }
  };

  return (
    <>
      {isLoading ? (
        <Loader />
      ) : (
        <div data-testid="search-container">
          {totalValue > 0 || showOnboardingTemplate || showOnlyChildren ? (
            <>
              {children}
              {!showOnlyChildren ? (
                <>
                  <ResultCount />
                  {data.length > 0 ? (
                    <div
                      className="tw-grid tw-grid-rows-1 tw-grid-cols-1"
                      data-testid="search-results">
                      {highlightSearchResult()}
                      {totalValue > PAGE_SIZE && data.length > 0 && (
                        <NextPrevious
                          isNumberBased
                          currentPage={currentPage}
                          pageSize={PAGE_SIZE}
                          paging={{} as Paging}
                          pagingHandler={paginate}
                          totalCount={totalValue}
                        />
                      )}
                    </div>
                  ) : (
                    <Onboarding />
                  )}
                </>
              ) : null}
            </>
          ) : (
            <>
              {children}
              <ErrorPlaceHolderES query={searchText} type="noData" />
            </>
          )}
        </div>
      )}
    </>
  );
};

SearchedData.propTypes = {
  children: PropTypes.element,
  data: PropTypes.array.isRequired,
  currentPage: PropTypes.number.isRequired,
  isLoading: PropTypes.bool,
  paginate: PropTypes.func.isRequired,
  showResultCount: PropTypes.bool,
  showOnboardingTemplate: PropTypes.bool,
  searchText: PropTypes.string,
  totalValue: PropTypes.number.isRequired,
  fetchLeftPanel: PropTypes.func,
};

export default SearchedData;
