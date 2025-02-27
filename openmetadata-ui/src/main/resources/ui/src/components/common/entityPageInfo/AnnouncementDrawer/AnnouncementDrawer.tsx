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

import { CloseOutlined } from '@ant-design/icons';
import { Button, Drawer, Space, Typography } from 'antd';
import { AxiosError } from 'axios';
import { Operation } from 'fast-json-patch';
import { observer } from 'mobx-react';
import React, { FC, useMemo, useState } from 'react';
import AppState from '../../../../AppState';
import { postFeedById, postThread } from '../../../../axiosAPIs/feedsAPI';
import {
  CreateThread,
  ThreadType,
} from '../../../../generated/api/feed/createThread';
import { getEntityFeedLink } from '../../../../utils/EntityUtils';
import { deletePost, updateThreadData } from '../../../../utils/FeedUtils';
import { showErrorToast } from '../../../../utils/ToastUtils';
import ActivityThreadPanelBody from '../../../ActivityFeed/ActivityThreadPanel/ActivityThreadPanelBody';
import AddAnnouncementModal from '../../../Modals/AddAnnouncementModal/AddAnnouncementModal';

interface Props {
  open: boolean;
  entityType: string;
  entityFQN: string;
  entityName: string;
  onClose: () => void;
}

const AnnouncementDrawer: FC<Props> = ({
  open,
  onClose,
  entityFQN,
  entityType,
  entityName,
}) => {
  const [isAnnouncement, setIsAnnouncement] = useState<boolean>(false);

  // get current user details
  const currentUser = useMemo(
    () => AppState.getCurrentUserDetails(),
    [AppState.userDetails, AppState.nonSecureUserDetails]
  );

  const title = (
    <Space
      className="tw-justify-between"
      data-testid="title"
      style={{ width: '100%' }}>
      <Typography.Text className="tw-font-medium">
        Announcement on {entityName}
      </Typography.Text>
      <CloseOutlined onClick={onClose} />
    </Space>
  );

  const createThread = (data: CreateThread) => {
    postThread(data).catch((err: AxiosError) => {
      showErrorToast(err);
    });
  };

  const deletePostHandler = (threadId: string, postId: string) => {
    deletePost(threadId, postId).catch((error: AxiosError) => {
      showErrorToast(error);
    });
  };

  const postFeedHandler = (value: string, id: string) => {
    const data = {
      message: value,
      from: currentUser?.name,
    };
    postFeedById(id, data).catch((err: AxiosError) => {
      showErrorToast(err);
    });
  };

  const updateThreadHandler = (
    threadId: string,
    postId: string,
    isThread: boolean,
    data: Operation[]
  ) => {
    const callback = () => {
      return;
    };

    updateThreadData(threadId, postId, isThread, data, callback);
  };

  return (
    <>
      <Drawer
        closable={false}
        data-testid="announcement-drawer"
        placement="right"
        title={title}
        visible={open}
        width={576}
        onClose={onClose}>
        <div className="tw-flex tw-justify-end">
          <Button
            data-testid="add-announcement"
            type="primary"
            onClick={() => setIsAnnouncement(true)}>
            Add Announcement
          </Button>
        </div>

        <ActivityThreadPanelBody
          className="tw-p-0"
          createThread={createThread}
          deletePostHandler={deletePostHandler}
          postFeedHandler={postFeedHandler}
          showHeader={false}
          threadLink={getEntityFeedLink(entityType, entityFQN)}
          threadType={ThreadType.Announcement}
          updateThreadHandler={updateThreadHandler}
        />
      </Drawer>

      {isAnnouncement && (
        <AddAnnouncementModal
          entityFQN={entityFQN || ''}
          entityType={entityType || ''}
          open={isAnnouncement}
          onCancel={() => setIsAnnouncement(false)}
        />
      )}
    </>
  );
};

export default observer(AnnouncementDrawer);
