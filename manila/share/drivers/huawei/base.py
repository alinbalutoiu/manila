# Copyright (c) 2015 Huawei Technologies Co., Ltd.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Abstract base class to work with share."""
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class HuaweiBase(object):
    """Interface to work with share."""

    def __init__(self, configuration):
        """Do initialization."""
        self.configuration = configuration

    @abc.abstractmethod
    def create_share(self, share, share_server):
        """Is called to create share."""

    @abc.abstractmethod
    def create_snapshot(self, snapshot, share_server):
        """Is called to create snapshot."""

    @abc.abstractmethod
    def delete_share(self, share, share_server):
        """Is called to remove share."""

    @abc.abstractmethod
    def delete_snapshot(self, snapshot, share_server):
        """Is called to remove snapshot."""

    @abc.abstractmethod
    def allow_access(self, share, access, share_server):
        """Allow access to the share."""

    @abc.abstractmethod
    def deny_access(self, share, access, share_server):
        """Deny access to the share."""

    @abc.abstractmethod
    def extend_share(self, share, new_size, share_server):
        """Extends size of existing share."""

    @abc.abstractmethod
    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""

    def update_share_stats(self, stats_dict):
        """Retrieve stats info from share group."""
