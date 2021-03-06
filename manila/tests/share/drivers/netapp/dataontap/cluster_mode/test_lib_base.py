# Copyright (c) 2015 Clinton Knight.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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
"""
Unit tests for the NetApp Data ONTAP cDOT base storage driver library.
"""

import copy
import socket
import time

import ddt
import mock
from oslo_log import log
from oslo_service import loopingcall

from manila import exception
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila.share.drivers.netapp import utils as na_utils
from manila.share import share_types
from manila.share import utils as share_utils
from manila import test
from manila.tests.share.drivers.netapp.dataontap import fakes as fake


@ddt.ddt
class NetAppFileStorageLibraryTestCase(test.TestCase):

    def setUp(self):
        super(NetAppFileStorageLibraryTestCase, self).setUp()

        self.mock_object(na_utils, 'validate_driver_instantiation')
        self.mock_object(na_utils, 'setup_tracing')

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(lib_base.LOG,
                         'info',
                         mock.Mock(side_effect=mock_logger.info))
        self.mock_object(lib_base.LOG,
                         'warning',
                         mock.Mock(side_effect=mock_logger.warning))
        self.mock_object(lib_base.LOG,
                         'error',
                         mock.Mock(side_effect=mock_logger.error))
        self.mock_object(lib_base.LOG,
                         'debug',
                         mock.Mock(side_effect=mock_logger.debug))

        kwargs = {
            'configuration': fake.get_config_cmode(),
            'app_version': fake.APP_VERSION
        }
        self.library = lib_base.NetAppCmodeFileStorageLibrary(fake.DRIVER_NAME,
                                                              **kwargs)
        self.library._client = mock.Mock()
        self.client = self.library._client
        self.context = mock.Mock()

    def test_init(self):
        self.assertEqual(fake.DRIVER_NAME, self.library.driver_name)
        self.assertEqual(1, na_utils.validate_driver_instantiation.call_count)
        self.assertEqual(1, na_utils.setup_tracing.call_count)
        self.assertIsNone(self.library._helpers)
        self.assertListEqual([], self.library._licenses)
        self.assertDictEqual({}, self.library._clients)
        self.assertDictEqual({}, self.library._ssc_stats)
        self.assertIsNotNone(self.library._app_version)

    def test_do_setup(self):
        mock_setup_helpers = self.mock_object(self.library, '_setup_helpers')
        mock_get_api_client = self.mock_object(self.library, '_get_api_client')

        self.library.do_setup(self.context)

        mock_get_api_client.assert_called_once_with()
        self.library._client.check_for_cluster_credentials.\
            assert_called_once_with()
        mock_setup_helpers.assert_called_once_with()

    def test_check_for_setup_error(self):

        self.library._licenses = []
        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['fake_license']))
        mock_start_periodic_tasks = self.mock_object(self.library,
                                                     '_start_periodic_tasks')

        self.library.check_for_setup_error()

        self.assertEqual(['fake_license'], self.library._licenses)
        mock_start_periodic_tasks.assert_called_once_with()

    def test_get_vserver(self):
        self.assertRaises(NotImplementedError, self.library._get_vserver)

    def test_get_api_client(self):

        client_kwargs = fake.CLIENT_KWARGS.copy()

        # First call should proceed normally.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client1 = self.library._get_api_client()
        self.assertIsNotNone(client1)
        mock_client_constructor.assert_called_once_with(**client_kwargs)

        # Second call should yield the same object.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client2 = self.library._get_api_client()
        self.assertEqual(client1, client2)
        self.assertFalse(mock_client_constructor.called)

    def test_get_api_client_with_vserver(self):

        client_kwargs = fake.CLIENT_KWARGS.copy()
        client_kwargs['vserver'] = fake.VSERVER1

        # First call should proceed normally.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client1 = self.library._get_api_client(vserver=fake.VSERVER1)
        self.assertIsNotNone(client1)
        mock_client_constructor.assert_called_once_with(**client_kwargs)

        # Second call should yield the same object.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client2 = self.library._get_api_client(vserver=fake.VSERVER1)
        self.assertEqual(client1, client2)
        self.assertFalse(mock_client_constructor.called)

        # A different vserver should work normally without caching.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client3 = self.library._get_api_client(vserver=fake.VSERVER2)
        self.assertNotEqual(client1, client3)
        client_kwargs['vserver'] = fake.VSERVER2
        mock_client_constructor.assert_called_once_with(**client_kwargs)

    def test_get_licenses_both_protocols(self):
        self.library._have_cluster_creds = True
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=fake.LICENSES))

        result = self.library._get_licenses()

        self.assertSequenceEqual(fake.LICENSES, result)
        self.assertEqual(0, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_one_protocol(self):
        self.library._have_cluster_creds = True
        licenses = list(fake.LICENSES)
        licenses.remove('nfs')
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=licenses))

        result = self.library._get_licenses()

        self.assertListEqual(licenses, result)
        self.assertEqual(0, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_no_protocols(self):
        self.library._have_cluster_creds = True
        licenses = list(fake.LICENSES)
        licenses.remove('nfs')
        licenses.remove('cifs')
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=licenses))

        result = self.library._get_licenses()

        self.assertListEqual(licenses, result)
        self.assertEqual(1, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_no_cluster_creds(self):
        self.library._have_cluster_creds = False

        result = self.library._get_licenses()

        self.assertListEqual([], result)
        self.assertEqual(1, lib_base.LOG.debug.call_count)

    def test_start_periodic_tasks(self):

        mock_update_ssc_info = self.mock_object(self.library,
                                                '_update_ssc_info')
        mock_handle_ems_logging = self.mock_object(self.library,
                                                   '_handle_ems_logging')
        mock_handle_housekeeping_tasks = self.mock_object(
            self.library, '_handle_housekeeping_tasks')
        mock_ssc_periodic_task = mock.Mock()
        mock_ems_periodic_task = mock.Mock()
        mock_housekeeping_periodic_task = mock.Mock()
        mock_loopingcall = self.mock_object(
            loopingcall,
            'FixedIntervalLoopingCall',
            mock.Mock(side_effect=[mock_ssc_periodic_task,
                                   mock_ems_periodic_task,
                                   mock_housekeeping_periodic_task]))

        self.library._start_periodic_tasks()

        self.assertTrue(mock_update_ssc_info.called)
        self.assertFalse(mock_handle_ems_logging.called)
        self.assertFalse(mock_housekeeping_periodic_task.called)
        mock_loopingcall.assert_has_calls(
            [mock.call(mock_update_ssc_info),
             mock.call(mock_handle_ems_logging),
             mock.call(mock_handle_housekeeping_tasks)])
        self.assertTrue(mock_ssc_periodic_task.start.called)
        self.assertTrue(mock_ems_periodic_task.start.called)
        self.assertTrue(mock_housekeeping_periodic_task.start.called)

    def test_get_valid_share_name(self):

        result = self.library._get_valid_share_name(fake.SHARE_ID)
        expected = (fake.VOLUME_NAME_TEMPLATE %
                    {'share_id': fake.SHARE_ID.replace('-', '_')})

        self.assertEqual(expected, result)

    def test_get_valid_snapshot_name(self):

        result = self.library._get_valid_snapshot_name(fake.SNAPSHOT_ID)
        expected = 'share_snapshot_' + fake.SNAPSHOT_ID.replace('-', '_')

        self.assertEqual(expected, result)

    def test_get_aggregate_space_cluster_creds(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library._client,
                         'get_cluster_aggregate_capacities',
                         mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))

        result = self.library._get_aggregate_space()

        self.library._client.get_cluster_aggregate_capacities.\
            assert_called_once_with(fake.AGGREGATES)
        self.assertDictEqual(fake.AGGREGATE_CAPACITIES, result)

    def test_get_aggregate_space_no_cluster_creds(self):

        self.library._have_cluster_creds = False
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library._client,
                         'get_vserver_aggregate_capacities',
                         mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))

        result = self.library._get_aggregate_space()

        self.library._client.get_vserver_aggregate_capacities.\
            assert_called_once_with(fake.AGGREGATES)
        self.assertDictEqual(fake.AGGREGATE_CAPACITIES, result)

    def test_get_share_stats(self):

        self.mock_object(self.library,
                         '_get_pools',
                         mock.Mock(return_value=fake.POOLS))

        result = self.library.get_share_stats()

        expected = {
            'share_backend_name': fake.BACKEND_NAME,
            'driver_name': fake.DRIVER_NAME,
            'vendor_name': 'NetApp',
            'driver_version': '1.0',
            'netapp_storage_family': 'ontap_cluster',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 0.0,
            'free_capacity_gb': 0.0,
            'pools': fake.POOLS,
        }
        self.assertDictEqual(expected, result)

    def test_get_share_server_pools(self):

        self.mock_object(self.library,
                         '_get_pools',
                         mock.Mock(return_value=fake.POOLS))

        result = self.library.get_share_server_pools(fake.SHARE_SERVER)

        self.assertListEqual(fake.POOLS, result)

    def test_get_pools(self):

        self.mock_object(self.library,
                         '_get_aggregate_space',
                         mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))
        self.library._ssc_stats = fake.SSC_INFO

        result = self.library._get_pools()

        self.assertListEqual(fake.POOLS, result)

    def test_handle_ems_logging(self):

        self.mock_object(self.library,
                         '_build_ems_log_message',
                         mock.Mock(return_value=fake.EMS_MESSAGE))

        self.library._handle_ems_logging()

        self.library._client.send_ems_log_message.assert_called_with(
            fake.EMS_MESSAGE)

    def test_build_ems_log_message(self):

        self.mock_object(socket,
                         'getfqdn',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = self.library._build_ems_log_message()

        fake_ems_log = {
            'computer-name': fake.HOST_NAME,
            'event-id': '0',
            'event-source': 'Manila driver %s' % fake.DRIVER_NAME,
            'app-version': fake.APP_VERSION,
            'category': 'provisioning',
            'event-description': 'OpenStack Manila connected to cluster node',
            'log-level': '6',
            'auto-support': 'false'
        }
        self.assertDictEqual(fake_ems_log, result)

    def test_find_matching_aggregates(self):
        self.assertRaises(NotImplementedError,
                          self.library._find_matching_aggregates)

    def test_setup_helpers(self):

        self.mock_object(cifs_cmode,
                         'NetAppCmodeCIFSHelper',
                         mock.Mock(return_value='fake_cifs_helper'))
        self.mock_object(nfs_cmode,
                         'NetAppCmodeNFSHelper',
                         mock.Mock(return_value='fake_nfs_helper'))
        self.library._helpers = None

        self.library._setup_helpers()

        self.assertDictEqual({'CIFS': 'fake_cifs_helper',
                              'NFS': 'fake_nfs_helper'},
                             self.library._helpers)

    def test_get_helper(self):

        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        self.library._licenses = fake.LICENSES
        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = 'NFS'
        mock_check_license_for_protocol = self.mock_object(
            self.library, '_check_license_for_protocol')

        result = self.library._get_helper(fake_share)

        mock_check_license_for_protocol.assert_called_once_with('NFS')
        self.assertEqual('fake_nfs_helper', result)

    def test_get_helper_invalid_protocol(self):

        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = 'iSCSI'
        self.mock_object(self.library, '_check_license_for_protocol')

        self.assertRaises(exception.NetAppException,
                          self.library._get_helper,
                          fake_share)

    def test_check_license_for_protocol_no_cluster_creds(self):

        self.library._have_cluster_creds = False

        result = self.library._check_license_for_protocol('fake_protocol')

        self.assertIsNone(result)

    def test_check_license_for_protocol_have_license(self):

        self.library._have_cluster_creds = True
        self.library._licenses = ['base', 'fake_protocol']

        result = self.library._check_license_for_protocol('FAKE_PROTOCOL')

        self.assertIsNone(result)

    def test_check_license_for_protocol_newly_licensed_protocol(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['base', 'nfs']))
        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        self.library._licenses = ['base']

        result = self.library._check_license_for_protocol('NFS')

        self.assertIsNone(result)
        self.assertTrue(self.library._get_licenses.called)

    def test_check_license_for_protocol_unlicensed_protocol(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['base']))
        self.library._helpers = {'CIFS': 'fake_cifs_helper',
                                 'NFS': 'fake_nfs_helper'}
        self.library._licenses = ['base']

        self.assertRaises(exception.NetAppException,
                          self.library._check_license_for_protocol,
                          'NFS')

    def test_get_pool_has_pool(self):
        result = self.library.get_pool(fake.SHARE)
        self.assertEqual(fake.POOL_NAME, result)
        self.assertFalse(self.client.get_aggregate_for_volume.called)

    def test_get_pool_no_pool(self):

        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = '%(host)s@%(backend)s' % {
            'host': fake.HOST_NAME, 'backend': fake.BACKEND_NAME}
        self.client.get_aggregate_for_volume.return_value = fake.POOL_NAME

        result = self.library.get_pool(fake_share)

        self.assertEqual(fake.POOL_NAME, result)
        self.assertTrue(self.client.get_aggregate_for_volume.called)

    def test_get_pool_raises(self):

        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = '%(host)s@%(backend)s' % {
            'host': fake.HOST_NAME, 'backend': fake.BACKEND_NAME}
        self.client.get_aggregate_for_volume.side_effect = (
            exception.NetAppException)

        self.assertRaises(exception.NetAppException,
                          self.library.get_pool,
                          fake_share)

    def test_create_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_allocate_container = self.mock_object(self.library,
                                                   '_allocate_container')
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value='fake_export_location'))

        result = self.library.create_share(self.context,
                                           fake.SHARE,
                                           share_server=fake.SHARE_SERVER)

        mock_allocate_container.assert_called_once_with(fake.SHARE,
                                                        vserver_client)
        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertEqual('fake_export_location', result)

    def test_create_share_from_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_allocate_container_from_snapshot = self.mock_object(
            self.library,
            '_allocate_container_from_snapshot')
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value='fake_export_location'))

        result = self.library.create_share_from_snapshot(
            self.context,
            fake.SHARE,
            fake.SNAPSHOT,
            share_server=fake.SHARE_SERVER)

        mock_allocate_container_from_snapshot.assert_called_once_with(
            fake.SHARE,
            fake.SNAPSHOT,
            vserver_client)
        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertEqual('fake_export_location', result)

    def test_allocate_container(self):
        self.mock_object(self.library, '_get_valid_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=fake.POOL_NAME))
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=fake.EXTRA_SPEC))

        self.mock_object(self.library, '_check_boolean_extra_specs_validity')
        self.mock_object(self.library, '_get_boolean_provisioning_options',
                         mock.Mock(return_value=fake.PROVISIONING_OPTIONS))
        vserver_client = mock.Mock()

        self.library._allocate_container(fake.EXTRA_SPEC_SHARE,
                                         vserver_client)

        vserver_client.create_volume.assert_called_once_with(
            fake.POOL_NAME, fake.SHARE_NAME, fake.SHARE['size'],
            thin_provisioned=True, snapshot_policy='default',
            language='en-US', dedup_enabled=True,
            compression_enabled=False, max_files=5000)

    def test_allocate_container_no_pool_name(self):
        self.mock_object(self.library, '_get_valid_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=None))
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_get_provisioning_options')
        vserver_client = mock.Mock()

        self.assertRaises(exception.InvalidHost,
                          self.library._allocate_container, fake.SHARE,
                          vserver_client)

        self.library._get_valid_share_name.assert_called_once_with(
            fake.SHARE['id'])
        share_utils.extract_host.assert_called_once_with(fake.SHARE['host'],
                                                         level='pool')
        self.assertEqual(0,
                         self.library._check_extra_specs_validity.call_count)
        self.assertEqual(0, self.library._get_provisioning_options.call_count)

    def test_check_extra_specs_validity(self):
        boolean_extra_spec_keys = list(
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)
        mock_bool_check = self.mock_object(
            self.library, '_check_boolean_extra_specs_validity')
        mock_string_check = self.mock_object(
            self.library, '_check_string_extra_specs_validity')

        self.library._check_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC)

        mock_bool_check.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC, boolean_extra_spec_keys)
        mock_string_check.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC)

    def test_check_extra_specs_validity_empty_spec(self):
        result = self.library._check_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EMPTY_EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.Invalid, self.library._check_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_EXTRA_SPEC)

    def test_check_string_extra_specs_validity(self):
        result = self.library._check_string_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_string_extra_specs_validity_empty_spec(self):
        result = self.library._check_string_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EMPTY_EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_string_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.NetAppException,
            self.library._check_string_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_MAX_FILE_EXTRA_SPEC)

    def test_check_boolean_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.Invalid,
            self.library._check_boolean_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_EXTRA_SPEC,
            list(self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP))

    def test_check_extra_specs_validity_invalid_combination(self):
        self.assertRaises(
            exception.Invalid,
            self.library._check_boolean_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_EXTRA_SPEC_COMBO,
            list(self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP))

    def test_get_provisioning_options(self):
        result = self.library._get_provisioning_options(fake.EXTRA_SPEC)

        self.assertEqual(fake.PROVISIONING_OPTIONS, result)

    def test_get_provisioning_options_missing_spec(self):
        result = self.library._get_provisioning_options(
            fake.SHORT_BOOLEAN_EXTRA_SPEC)

        self.assertEqual(
            fake.PROVISIONING_OPTIONS_BOOLEAN_THIN_PROVISIONED_TRUE, result)

    def test_get_provisioning_options_implicit_false(self):
        result = self.library._get_provisioning_options(
            fake.EMPTY_EXTRA_SPEC)

        expected = {
            'language': None,
            'max_files': None,
            'snapshot_policy': None,
            'thin_provisioned': False,
            'compression_enabled': False,
            'dedup_enabled': False,
        }

        self.assertEqual(expected, result)

    def test_get_boolean_provisioning_options(self):
        result = self.library._get_boolean_provisioning_options(
            fake.SHORT_BOOLEAN_EXTRA_SPEC,
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_BOOLEAN, result)

    def test_get_boolean_provisioning_options_missing_spec(self):
        result = self.library._get_boolean_provisioning_options(
            fake.SHORT_BOOLEAN_EXTRA_SPEC,
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_BOOLEAN, result)

    def test_get_boolean_provisioning_options_implicit_false(self):
        expected = {
            'thin_provisioned': False,
            'dedup_enabled': False,
            'compression_enabled': False,
        }

        result = self.library._get_boolean_provisioning_options(
            fake.EMPTY_EXTRA_SPEC,
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(expected, result)

    def test_get_string_provisioning_options(self):
        result = self.library._get_string_provisioning_options(
            fake.STRING_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING, result)

    def test_get_string_provisioning_options_missing_spec(self):
        result = self.library._get_string_provisioning_options(
            fake.SHORT_STRING_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING_MISSING_SPECS,
                         result)

    def test_get_string_provisioning_options_implicit_false(self):
        result = self.library._get_string_provisioning_options(
            fake.EMPTY_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING_DEFAULT, result)

    def test_check_if_max_files_is_valid_with_negative_integer(self):
        self.assertRaises(exception.NetAppException,
                          self.library._check_if_max_files_is_valid,
                          fake.SHARE, -1)

    def test_check_if_max_files_is_valid_with_string(self):
        self.assertRaises(ValueError,
                          self.library._check_if_max_files_is_valid,
                          fake.SHARE, 'abc')

    def test_allocate_container_no_pool(self):

        vserver_client = mock.Mock()
        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = fake_share['host'].split('#')[0]

        self.assertRaises(exception.InvalidHost,
                          self.library._allocate_container,
                          fake_share,
                          vserver_client)

    def test_allocate_container_from_snapshot(self):

        vserver_client = mock.Mock()

        self.library._allocate_container_from_snapshot(fake.SHARE,
                                                       fake.SNAPSHOT,
                                                       vserver_client)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        parent_share_name = self.library._get_valid_share_name(
            fake.SNAPSHOT['share_id'])
        parent_snapshot_name = self.library._get_valid_snapshot_name(
            fake.SNAPSHOT['id'])
        vserver_client.create_volume_clone.assert_called_once_with(
            share_name,
            parent_share_name,
            parent_snapshot_name)
        vserver_client.split_volume_clone.assert_called_once_with(share_name)

    def test_share_exists(self):

        vserver_client = mock.Mock()
        vserver_client.volume_exists.return_value = True

        result = self.library._share_exists(fake.SHARE_NAME, vserver_client)

        self.assertTrue(result)

    def test_share_exists_not_found(self):

        vserver_client = mock.Mock()
        vserver_client.volume_exists.return_value = False

        result = self.library._share_exists(fake.SHARE_NAME, vserver_client)

        self.assertFalse(result)

    def test_delete_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=True))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        mock_remove_export.assert_called_once_with(fake.SHARE, vserver_client)
        mock_deallocate_container.assert_called_once_with(share_name,
                                                          vserver_client)
        self.assertEqual(0, lib_base.LOG.info.call_count)

    @ddt.data(exception.InvalidInput(reason='fake_reason'),
              exception.VserverNotSpecified(),
              exception.VserverNotFound(vserver='fake_vserver'))
    def test_delete_share_no_share_server(self, get_vserver_exception):

        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(side_effect=get_vserver_exception))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=False))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        self.assertFalse(mock_share_exists.called)
        self.assertFalse(mock_remove_export.called)
        self.assertFalse(mock_deallocate_container.called)
        self.assertEqual(1, lib_base.LOG.warning.call_count)

    def test_delete_share_not_found(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=False))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        self.assertFalse(mock_remove_export.called)
        self.assertFalse(mock_deallocate_container.called)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_deallocate_container(self):

        vserver_client = mock.Mock()

        self.library._deallocate_container(fake.SHARE_NAME, vserver_client)

        vserver_client.unmount_volume.assert_called_with(fake.SHARE_NAME,
                                                         force=True)
        vserver_client.offline_volume.assert_called_with(fake.SHARE_NAME)
        vserver_client.delete_volume.assert_called_with(fake.SHARE_NAME)

    def test_create_export(self):

        protocol_helper = mock.Mock()
        protocol_helper.create_share.return_value = fake.NFS_EXPORTS
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()
        vserver_client.get_network_interfaces.return_value = fake.LIFS

        result = self.library._create_export(fake.SHARE,
                                             fake.VSERVER1,
                                             vserver_client)

        self.assertEqual(fake.NFS_EXPORTS, result)
        protocol_helper.create_share.assert_called_once_with(
            fake.SHARE, fake.SHARE_NAME, fake.LIF_ADDRESSES)

    def test_create_export_lifs_not_found(self):

        self.mock_object(self.library, '_get_helper')
        vserver_client = mock.Mock()
        vserver_client.get_network_interfaces.return_value = []

        self.assertRaises(exception.NetAppException,
                          self.library._create_export,
                          fake.SHARE,
                          fake.VSERVER1,
                          vserver_client)

    def test_remove_export(self):

        protocol_helper = mock.Mock()
        protocol_helper.get_target.return_value = 'fake_target'
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()

        self.library._remove_export(fake.SHARE, vserver_client)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.get_target.assert_called_once_with(fake.SHARE)
        protocol_helper.delete_share.assert_called_once_with(fake.SHARE,
                                                             fake.SHARE_NAME)

    def test_remove_export_target_not_found(self):

        protocol_helper = mock.Mock()
        protocol_helper.get_target.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()

        self.library._remove_export(fake.SHARE, vserver_client)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.get_target.assert_called_once_with(fake.SHARE)
        self.assertFalse(protocol_helper.delete_share.called)

    def test_create_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.library.create_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_valid_snapshot_name(
            fake.SNAPSHOT['id'])
        vserver_client.create_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)

    def test_delete_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_handle_busy_snapshot = self.mock_object(self.library,
                                                     '_handle_busy_snapshot')

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_valid_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_valid_snapshot_name(
            fake.SNAPSHOT['id'])
        self.assertTrue(mock_handle_busy_snapshot.called)
        vserver_client.delete_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)

    @ddt.data(exception.InvalidInput(reason='fake_reason'),
              exception.VserverNotSpecified(),
              exception.VserverNotFound(vserver='fake_vserver'))
    def test_delete_snapshot_no_share_server(self, get_vserver_exception):

        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(side_effect=get_vserver_exception))
        mock_handle_busy_snapshot = self.mock_object(self.library,
                                                     '_handle_busy_snapshot')

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        self.assertFalse(mock_handle_busy_snapshot.called)
        self.assertEqual(1, lib_base.LOG.warning.call_count)

    def test_delete_snapshot_not_found(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_handle_busy_snapshot = self.mock_object(
            self.library, '_handle_busy_snapshot',
            mock.Mock(side_effect=exception.SnapshotNotFound(
                name=fake.SNAPSHOT_NAME)))

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        self.assertTrue(mock_handle_busy_snapshot.called)
        self.assertFalse(vserver_client.delete_snapshot.called)

    def test_delete_snapshot_busy(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_handle_busy_snapshot = self.mock_object(
            self.library, '_handle_busy_snapshot',
            mock.Mock(side_effect=exception.ShareSnapshotIsBusy(
                snapshot_name=fake.SNAPSHOT_NAME)))

        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self.library.delete_snapshot,
                          self.context,
                          fake.SNAPSHOT,
                          share_server=fake.SHARE_SERVER)

        self.assertTrue(mock_handle_busy_snapshot.called)
        self.assertFalse(vserver_client.delete_snapshot.called)

    def test_handle_busy_snapshot_not_busy(self):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT

        result = self.library._handle_busy_snapshot(vserver_client,
                                                    fake.SHARE_NAME,
                                                    fake.SNAPSHOT_NAME)

        self.assertIsNone(result)
        self.assertEqual(1, vserver_client.get_snapshot.call_count)
        self.assertEqual(0, lib_base.LOG.debug.call_count)

    def test_handle_busy_snapshot_not_found(self):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.side_effect = exception.SnapshotNotFound(
            name=fake.SNAPSHOT_NAME)

        self.assertRaises(exception.SnapshotNotFound,
                          self.library._handle_busy_snapshot,
                          vserver_client,
                          fake.SHARE_NAME,
                          fake.SNAPSHOT_NAME)

    def test_handle_busy_snapshot_not_clone_dependency(self):

        snapshot = copy.deepcopy(fake.CDOT_SNAPSHOT_BUSY_VOLUME_CLONE)
        snapshot['owners'] = {'fake reason'}

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = snapshot

        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self.library._handle_busy_snapshot,
                          vserver_client,
                          fake.SHARE_NAME,
                          fake.SNAPSHOT_NAME)
        self.assertEqual(1, vserver_client.get_snapshot.call_count)
        self.assertEqual(0, lib_base.LOG.debug.call_count)

    def test_handle_busy_snapshot_clone_finishes(self):

        get_snapshot_side_effect = [fake.CDOT_SNAPSHOT_BUSY_VOLUME_CLONE] * 10
        get_snapshot_side_effect.append(fake.CDOT_SNAPSHOT)

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.side_effect = get_snapshot_side_effect
        mock_sleep = self.mock_object(time, 'sleep')

        result = self.library._handle_busy_snapshot(vserver_client,
                                                    fake.SHARE_NAME,
                                                    fake.SNAPSHOT_NAME)

        self.assertIsNone(result)
        self.assertEqual(11, vserver_client.get_snapshot.call_count)
        mock_sleep.assert_has_calls([mock.call(3)] * 10)
        self.assertEqual(10, lib_base.LOG.debug.call_count)

    def test_handle_busy_snapshot_clone_continues(self):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.side_effect = [
            fake.CDOT_SNAPSHOT_BUSY_VOLUME_CLONE] * 30
        mock_sleep = self.mock_object(time, 'sleep')

        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self.library._handle_busy_snapshot,
                          vserver_client,
                          fake.SHARE_NAME,
                          fake.SNAPSHOT_NAME)
        self.assertEqual(21, vserver_client.get_snapshot.call_count)
        mock_sleep.assert_has_calls([mock.call(3)] * 20)
        self.assertEqual(20, lib_base.LOG.debug.call_count)

    def test_extend_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_set_volume_size = self.mock_object(vserver_client,
                                                'set_volume_size')
        new_size = fake.SHARE['size'] * 2

        self.library.extend_share(fake.SHARE, new_size)

        mock_set_volume_size.assert_called_once_with(fake.SHARE_NAME, new_size)

    def test_shrink_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_set_volume_size = self.mock_object(vserver_client,
                                                'set_volume_size')
        new_size = fake.SHARE['size'] - 1

        self.library.shrink_share(fake.SHARE, new_size)

        mock_set_volume_size.assert_called_once_with(fake.SHARE_NAME, new_size)

    def test_allow_access(self):

        protocol_helper = mock.Mock()
        protocol_helper.allow_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.library.allow_access(self.context,
                                  fake.SHARE,
                                  fake.SHARE_ACCESS,
                                  share_server=fake.SHARE_SERVER)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.allow_access.assert_called_once_with(
            self.context,
            fake.SHARE,
            fake.SHARE_NAME,
            fake.SHARE_ACCESS)

    def test_deny_access(self):

        protocol_helper = mock.Mock()
        protocol_helper.deny_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.library.deny_access(self.context,
                                 fake.SHARE,
                                 fake.SHARE_ACCESS,
                                 share_server=fake.SHARE_SERVER)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.deny_access.assert_called_once_with(
            self.context,
            fake.SHARE,
            fake.SHARE_NAME,
            fake.SHARE_ACCESS)

    def test_setup_server(self):
        self.assertRaises(NotImplementedError,
                          self.library.setup_server,
                          fake.NETWORK_INFO)

    def test_teardown_server(self):
        self.assertRaises(NotImplementedError,
                          self.library.teardown_server,
                          fake.SHARE_SERVER['backend_details'])

    def test_get_network_allocations_number(self):
        self.assertRaises(NotImplementedError,
                          self.library.get_network_allocations_number)

    def test_update_ssc_info(self):

        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_update_ssc_aggr_info = self.mock_object(self.library,
                                                     '_update_ssc_aggr_info')

        self.library._update_ssc_info()

        expected = {
            fake.AGGREGATES[0]: {},
            fake.AGGREGATES[1]: {}
        }

        self.assertDictEqual(expected, self.library._ssc_stats)
        self.assertTrue(mock_update_ssc_aggr_info.called)

    def test_update_ssc_info_no_aggregates(self):

        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=[]))
        mock_update_ssc_aggr_info = self.mock_object(self.library,
                                                     '_update_ssc_aggr_info')

        self.library._update_ssc_info()

        self.assertDictEqual({}, self.library._ssc_stats)
        self.assertFalse(mock_update_ssc_aggr_info.called)

    def test_update_ssc_aggr_info(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.client,
                         'get_aggregate_raid_types',
                         mock.Mock(return_value=fake.SSC_RAID_TYPES))
        self.mock_object(self.client,
                         'get_aggregate_disk_types',
                         mock.Mock(return_value=fake.SSC_DISK_TYPES))
        ssc_stats = {
            fake.AGGREGATES[0]: {},
            fake.AGGREGATES[1]: {}
        }

        self.library._update_ssc_aggr_info(fake.AGGREGATES, ssc_stats)

        self.assertDictEqual(fake.SSC_INFO, ssc_stats)

    def test_update_ssc_aggr_info_not_found(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.client,
                         'get_aggregate_raid_types',
                         mock.Mock(return_value={}))
        self.mock_object(self.client,
                         'get_aggregate_disk_types',
                         mock.Mock(return_value={}))
        ssc_stats = {}

        self.library._update_ssc_aggr_info(fake.AGGREGATES, ssc_stats)

        self.assertDictEqual({}, ssc_stats)

    def test_update_ssc_aggr_info_no_cluster_creds(self):

        self.library._have_cluster_creds = False
        ssc_stats = {}

        self.library._update_ssc_aggr_info(fake.AGGREGATES, ssc_stats)

        self.assertDictEqual({}, ssc_stats)
        self.assertFalse(self.library._client.get_aggregate_raid_types.called)
