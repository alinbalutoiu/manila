# Copyright (c) 2015 Cloudbase Solutions SRL
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

from manila import exception
from manila.share.configuration import Configuration
from manila.share.drivers import generic
from manila.share.drivers.windows import service_instance
from manila.share.drivers.windows import windows
from manila.share.drivers.windows.windows import WindowsSMBDriver
from manila.share.drivers.windows import windows_smb_helper
from manila.share.drivers.windows import windows_utils
from manila.share.drivers.windows import winrm_helper
from manila import test
import mock


class WindowsSMBDriverTestCase(test.TestCase):
    @mock.patch.object(winrm_helper, 'WinRMHelper')
    @mock.patch.object(windows_utils, 'WindowsUtils')
    @mock.patch.object(windows_smb_helper, 'WindowsSMBHelper')
    def setUp(self, mock_helper_cls, mock_utils_cls, mock_winrm_helper_cls):
        self.flags(driver_handles_share_servers=False)

        self.fake_conf = Configuration(None)
        with mock.patch.object(service_instance,
                               'WindowsServiceInstanceManager'):
            self._windows = windows.WindowsSMBDriver(
                configuration=self.fake_conf)

        self._DEFAULT_SHARE_PARTITION = self._windows._DEFAULT_SHARE_PARTITION
        self._remote_execute = mock_winrm_helper_cls.return_value
        self._windows_utils = mock_utils_cls.return_value
        self._smb_helper = mock_helper_cls.return_value
        super(WindowsSMBDriverTestCase, self).setUp()

    @mock.patch('manila.share.driver.ShareDriver')
    def test_update_share_stats(self, mock_driver):
        self._windows._update_share_stats()
        mock_driver._update_share_stats.assert_called_once_with(
            self._windows,
            data=dict(storage_protocol="CIFS"))

    @mock.patch.object(service_instance, 'WindowsServiceInstanceManager')
    def test_setup_service_instance_manager(self, mock_service):
        self._windows._setup_service_instance_manager()
        mock_service.assert_called_once_with(driver_config=self.fake_conf)

    def test_setup_helpers(self):
        expected_result = {"SMB": self._smb_helper,
                           "CIFS": self._smb_helper}
        self._windows._setup_helpers()
        self.assertEqual(expected_result, self._windows._helpers)

    @mock.patch.object(generic.GenericShareDriver, '_teardown_server')
    def _test_teardown_server(self, mock_teardown,
                              security_service_valid=True):
        func = self._windows.service_instance_manager
        mock_server = {'joined_domain': True}
        mock_sec_services = {'user': mock.sentinel.user,
                             'password': mock.sentinel.password}

        if security_service_valid:
            func.get_valid_security_service.return_value = mock_sec_services
            self._windows._teardown_server(mock_server,
                                           mock_sec_services)

            func.get_valid_security_service.assert_called_once_with(
                mock_sec_services)
            self._windows_utils.unjoin_domain.assert_called_once_with(
                mock_server,
                mock_sec_services['user'],
                mock_sec_services['password'])
        else:
            func.get_valid_security_service.return_value = None
            self._windows._teardown_server(mock_server,
                                           mock_sec_services)
        mock_teardown.assert_called_once_with(mock_server,
                                              mock_sec_services)

    def test_teardown_valid_security_services(self):
        self._test_teardown_server()

    def test_teardown_invalid_security_services(self):
        self._test_teardown_server(security_service_valid=False)

    @mock.patch.object(WindowsSMBDriver, '_get_disk_number')
    def test_format_device(self, mock_get_disk):
        mock_get_disk.return_value = mock.sentinel.disk_number
        self._windows._format_device(mock.sentinel.server, mock.sentinel.vol)

        self._windows._get_disk_number.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.vol)

        self._windows_utils.initialize_disk.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)

        self._windows_utils.create_partition.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)

        self._windows_utils.format_partition.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number,
            self._DEFAULT_SHARE_PARTITION)

    @mock.patch.object(WindowsSMBDriver, '_ensure_disk_online_and_writable')
    @mock.patch.object(WindowsSMBDriver, '_get_disk_number')
    @mock.patch.object(WindowsSMBDriver, '_get_mount_path')
    @mock.patch.object(WindowsSMBDriver, '_is_device_mounted')
    def _test_mount_device(self, mock_device_mounted, mock_mount_path,
                           mock_get_disk, mock_ensure_disk, is_mounted=True):
        mock_mount_path.return_value = mock.sentinel.path
        mock_device_mounted.return_value = is_mounted
        mock_get_disk.return_value = mock.sentinel.disk_number

        self._windows._mount_device(share=mock.sentinel.share,
                                    server_details=mock.sentinel.server,
                                    volume=mock.sentinel.vol)

        windows = self._windows
        windows._is_device_mounted.assert_called_once_with(
            mock.sentinel.path, mock.sentinel.server, mock.sentinel.vol)

        if not is_mounted:
            mock_get_disk.return_value = mock.sentinel.disk_number

            self._windows._get_disk_number.assert_called_once_with(
                mock.sentinel.server, mock.sentinel.vol)

            called = self._windows_utils
            called.ensure_directory_exists.assert_called_once_with(
                mock.sentinel.server, mock.sentinel.path)
            called.add_access_path(mock.sentinel.server,
                                   mock.sentinel.path,
                                   mock.sentinel.disk_number,
                                   self._DEFAULT_SHARE_PARTITION)

            windows._ensure_disk_online_and_writable.assert_called_once_with(
                mock.sentinel.server, mock.sentinel.disk_number)

    def test_mount_device_mounted(self):
        self._test_mount_device()

    def test_moune_device_not_mounted(self):
        self._test_mount_device(is_mounted=False)

    @mock.patch.object(WindowsSMBDriver, '_get_mount_path')
    def _test_unmount_device(self, mock_mount_path, disk_number=None):
        mock_mount_path.return_value = mock.sentinel.path

        self._windows._unmount_device(mock.sentinel.share,
                                      mock.sentinel.server)

        mock_mount_path.assert_called_once_with(mock.sentinel.share)

        called = self._windows_utils
        called.get_disk_number_by_mount_path.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.path)

        if disk_number:
            called.set_disk_online_status.assert_called_once_with(
                mock.sentinel.server, disk_number=disk_number, online=False)

    def test_unmount_device_with_disk_number(self):
        self._test_unmount_device(disk_number=0)

    def test_unmount_device_without_disk_number(self):
        self._test_unmount_device()

    @mock.patch.object(WindowsSMBDriver, '_get_disk_number')
    @mock.patch.object(WindowsSMBDriver, '_ensure_disk_online_and_writable')
    def test_resize_filesystem(self, mock_ensure_disk, mock_get_disk):
        mock_get_disk.return_value = mock.sentinel.disk_number
        mock_ensure_disk.return_value = mock.sentinel.disk_online

        func = self._windows_utils.get_partition_maximum_size
        func.return_value = mock.sentinel.size

        windows = self._windows
        windows._resize_filesystem(mock.sentinel.server,
                                   mock.sentinel.vol)

        mock_get_disk.assert_called_once_with(mock.sentinel.server,
                                              mock.sentinel.vol)
        windows._ensure_disk_online_and_writable.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)
        self._windows_utils.get_partition_maximum_size.assert_called_once_with(
            mock.sentinel.server,
            mock.sentinel.disk_number,
            self._DEFAULT_SHARE_PARTITION)
        self._windows_utils.resize_partition.assert_called_once_with(
            mock.sentinel.server,
            mock.sentinel.size,
            mock.sentinel.disk_number,
            self._DEFAULT_SHARE_PARTITION)

    def test_ensure_disk_online_and_writable(self):
        self._windows._ensure_disk_online_and_writable(
            mock.sentinel.server, mock.sentinel.disk_number)

        windows = self._windows_utils
        windows.update_disk.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number)
        windows.set_disk_online_status.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number, online=True)
        windows.set_disk_readonly_status.assert_called_once_with(
            mock.sentinel.server, mock.sentinel.disk_number, readonly=False)

    @mock.patch('oslo_utils.units.Gi')
    def test_get_mounted_share_size(self, mock_units):
        func = self._windows_utils.get_disk_size_by_path
        func.return_value = 10

        result = self._windows._get_mounted_share_size(mock.sentinel.path,
                                                       mock.sentinel.server)
        expected_result = 10 / mock_units
        self.assertEqual(expected_result, result)

    @mock.patch('os.path.join')
    def test_get_mount_path(self, mocked_join):
        mocked_join.return_value = mock.sentinel.join
        self._windows_utils.normalize_path.return_value = mock.sentinel.path

        mock_share = {'name': "username"}
        result = self._windows._get_mount_path(mock_share)

        mocked_join.assert_called_once_with(
            self._windows.configuration.share_mount_path, mock_share['name'])
        self.assertEqual(mock.sentinel.path, result)

    def _test_get_disk_number(self, disk_number=None):
        func = self._windows_utils.get_disk_number_by_serial_number
        func.return_value = disk_number
        mock_volume = {'id': 0,
                       'mountpoint': "/dev/hdX"}

        result = self._windows._get_disk_number(mock.sentinel.server,
                                                mock_volume)

        func.assert_called_once_with(mock.sentinel.server, mock_volume['id'])
        if disk_number is None:
            expected_result = ord(mock_volume['mountpoint'][-1]) - ord('a')
            self.assertEqual(expected_result, result)
        else:
            self.assertEqual(disk_number, result)

    def test_get_disk_without_number(self):
        self._test_get_disk_number()

    def test_get_disk_with_number(self):
        self._test_get_disk_number(disk_number=0)

    def _test_is_device_mounted(self, disk_number=None, volume=False,
                                expected_disk_number=None, expect_exc=True):
        func = self._windows_utils.get_disk_number_by_mount_path
        func.return_value = disk_number

        if disk_number is None:
            self.assertFalse(self._windows._is_device_mounted(
                mount_path=mock.sentinel.path,
                server_details=mock.sentinel.server))
        elif volume:
            func_serial = self._windows_utils.get_disk_number_by_serial_number
            func_serial.return_value = expected_disk_number
            mock_volume = {'id': 0}
            if disk_number != expected_disk_number:
                self.assertRaises(exception.ShareBackendException,
                                  self._windows._is_device_mounted,
                                  mount_path=mock.sentinel.path,
                                  server_details=mock.sentinel.server,
                                  volume=mock_volume)
            func_serial.assert_called_once_with(mock.sentinel.server,
                                                mock_volume['id'])
        if not expect_exc:
            self.assertTrue(
                self._windows._is_device_mounted(
                    mount_path=mock.sentinel.path,
                    server_details=mock.sentinel.server))
        func.assert_called_once_with(mock.sentinel.server, mock.sentinel.path)

    def test_is_device_mounted(self):
        self._test_is_device_mounted(disk_number=0,
                                     expect_exc=False)

    def test_is_device_without_number(self):
        self._test_is_device_mounted()

    def test_is_device_without_volume(self):
        self._test_is_device_mounted(disk_number=1,
                                     expect_exc=False)

    def test_is_device_diff_disk_number(self):
        self._test_is_device_mounted(disk_number=1,
                                     expected_disk_number=2,
                                     volume=True,
                                     expect_exc=True)
