# Copyright (c) 2015 EMC Corporation.
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

from oslo_log import log
from oslo_serialization import jsonutils
import requests
import six

LOG = log.getLogger(__name__)


class IsilonApi(object):

    def __init__(self, api_url, auth, verify_ssl_cert=True):
        self.host_url = api_url
        self.session = requests.session()
        self.session.auth = auth
        self.verify_ssl_cert = verify_ssl_cert

    def create_directory(self, container_path, recursive=False):
        """Create a directory."""

        headers = {"x-isi-ifs-target-type": "container"}
        url = (self.host_url + "/namespace" + container_path + '?recursive='
               + six.text_type(recursive))
        r = self.request('PUT', url,
                         headers=headers)
        return r.status_code == 200

    def clone_snapshot(self, snapshot_name, fq_target_dir):
        self.create_directory(fq_target_dir)
        snapshot = self.get_snapshot(snapshot_name)
        snapshot_path = snapshot['path']
        # remove /ifs from start of path
        relative_snapshot_path = snapshot_path[4:]
        fq_snapshot_path = ('/ifs/.snapshot/' + snapshot_name +
                            relative_snapshot_path)
        self._clone_directory_contents(fq_snapshot_path, fq_target_dir,
                                       snapshot_name, relative_snapshot_path)

    def _clone_directory_contents(self, fq_source_dir, fq_target_dir,
                                  snapshot_name, relative_path):
        dir_listing = self.get_directory_listing(fq_source_dir)
        for item in dir_listing['children']:
            name = item['name']
            source_item_path = fq_source_dir + '/' + name
            new_relative_path = relative_path + '/' + name
            dest_item_path = fq_target_dir + '/' + name
            if item['type'] == 'container':
                # create the container name in the target dir & clone dir
                self.create_directory(dest_item_path)
                self._clone_directory_contents(source_item_path,
                                               dest_item_path,
                                               snapshot_name,
                                               new_relative_path)
            elif item['type'] == 'object':
                self.clone_file_from_snapshot('/ifs' + new_relative_path,
                                              dest_item_path, snapshot_name)

    def clone_file_from_snapshot(self, fq_file_path, fq_dest_path,
                                 snapshot_name):
        headers = {'x-isi-ifs-copy-source': '/namespace' + fq_file_path}
        snapshot_suffix = '&snapshot=' + snapshot_name
        url = (self.host_url + '/namespace' + fq_dest_path + '?clone=true' +
               snapshot_suffix)
        self.request('PUT', url, headers=headers)

    def get_directory_listing(self, fq_dir_path):
        url = self.host_url + '/namespace' + fq_dir_path + '?detail=default'
        r = self.request('GET', url)

        r.raise_for_status()
        return r.json()

    def is_path_existent(self, resource_path):
        url = self.host_url + '/namespace' + resource_path
        r = self.request('HEAD', url)
        if r.status_code == 200:
            return True
        elif r.status_code == 404:
            return False
        else:
            r.raise_for_status()

    def get_snapshot(self, snapshot_name):
        r = self.request('GET',
                         self.host_url + '/platform/1/snapshot/snapshots/' +
                         snapshot_name)
        snapshot_json = r.json()
        if r.status_code == 200:
            return snapshot_json['snapshots'][0]
        elif r.status_code == 404:
            return None
        else:
            r.raise_for_status()

    def get_snapshots(self):
        r = self.request('GET',
                         self.host_url + '/platform/1/snapshot/snapshots')
        if r.status_code == 200:
            return r.json()
        else:
            r.raise_for_status()

    def lookup_nfs_export(self, share_path):
        response = self.session.get(
            self.host_url + '/platform/1/protocols/nfs/exports',
            verify=self.verify_ssl_cert)
        nfs_exports_json = response.json()
        for export in nfs_exports_json['exports']:
            for path in export['paths']:
                if path == share_path:
                    return export['id']
        return None

    def get_nfs_export(self, export_id):
        response = self.request('GET',
                                self.host_url +
                                '/platform/1/protocols/nfs/exports/' +
                                six.text_type(export_id))
        if response.status_code == 200:
            return response.json()['exports'][0]
        else:
            return None

    def lookup_smb_share(self, share_name):
        response = self.session.get(
            self.host_url + '/platform/1/protocols/smb/shares/' + share_name)
        if response.status_code == 200:
            return response.json()['shares'][0]
        else:
            return None

    def create_nfs_export(self, export_path):
        """Creates an NFS export using the Platform API.

        :param export_path: a string specifying the desired export path
        :return: "True" if created successfully; "False" otherwise
        """

        data = {'paths': [export_path]}
        url = self.host_url + '/platform/1/protocols/nfs/exports'
        response = self.request('POST', url, data=data)
        return response.status_code == 201

    def create_smb_share(self, share_name, share_path):
        """Creates an SMB/CIFS share.

        :param share_name: the name of the CIFS share
        :param share_path: the path associated with the CIFS share
        :return: "True" if the share created successfully; returns "False"
        otherwise
        """

        data = {}
        data['name'] = share_name
        data['path'] = share_path
        url = self.host_url + '/platform/1/protocols/smb/shares'
        response = self.request('POST', url, data=data)
        return response.status_code == 201

    def create_snapshot(self, snapshot_name, snapshot_path):
        """Creates a snapshot."""

        data = {'name': snapshot_name, 'path': snapshot_path}
        r = self.request('POST',
                         self.host_url + '/platform/1/snapshot/snapshots',
                         data=data)
        if r.status_code == 201:
            return True
        else:
            r.raise_for_status()

    def delete(self, fq_resource_path, recursive=False):
        """Deletes a file or folder."""

        r = self.request('DELETE',
                         self.host_url + '/namespace' + fq_resource_path +
                         '?recursive=' + six.text_type(recursive))
        r.raise_for_status()

    def delete_nfs_share(self, share_number):
        response = self.session.delete(
            self.host_url + '/platform/1/protocols/nfs/exports' + '/' +
            six.text_type(share_number))
        return response.status_code == 204

    def delete_smb_share(self, share_name):
        url = self.host_url + '/platform/1/protocols/smb/shares/' + share_name
        response = self.request('DELETE', url)
        return response.status_code == 204

    def delete_snapshot(self, snapshot_name):
        response = self.request(
            'DELETE', '{0}/platform/1/snapshot/snapshots/{1}'
            .format(self.host_url, snapshot_name))
        response.raise_for_status()

    def request(self, method, url, headers=None, data=None):
        if data is not None:
            data = jsonutils.dumps(data)
        r = self.session.request(method, url, headers=headers, data=data,
                                 verify=self.verify_ssl_cert)
        return r
