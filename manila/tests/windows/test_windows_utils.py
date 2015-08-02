import mock

from manila import test
from manila.share.drivers.windows import windows_utils


class WindowsUtilsTestCase(test.TestCase):
    def setUp(self):
        self._remote_exec = mock.MagicMock()
        self._windows_utils = windows_utils.WindowsUtils(self._remote_exec)
        super(WindowsUtilsTestCase, self).setUp()

    def test_initialize_disk(self):
        self._windows_utils.initialize_disk(mock.sentinel.server,
                                            mock.sentinel.disk_number)

        cmd = ["Initialize-Disk", "-Number", mock.sentinel.disk_number]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_create_partition(self):
        self._windows_utils.create_partition(mock.sentinel.server,
                                             mock.sentinel.disk_number)

        cmd = ["New-Partition", "-DiskNumber",
               mock.sentinel.disk_number, "-UseMaximumSize"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  cmd)

    def test_format_partition(self):
        self._windows_utils.format_partition(mock.sentinel.server,
                                             mock.sentinel.disk_number,
                                             mock.sentinel.partition_number)
        cmd = ("Get-Partition -DiskNumber %(disk_number)s "
               "-PartitionNumber %(partition_number)s | "
               "Format-Volume -FileSystem NTFS -Force -Confirm:$false" % {
                   'disk_number': mock.sentinel.disk_number,
                   'partition_number': mock.sentinel.partition_number,
               })
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  cmd)

    @mock.patch.object(windows_utils.WindowsUtils, '_quote_string')
    def test_add_access_path(self, mock_quote_string):
        mock_quote_string.return_value = mock.sentinel.quote_string

        self._windows_utils.add_access_path(mock.sentinel.server,
                                            mock.sentinel.mount_path,
                                            mock.sentinel.disk_number,
                                            mock.sentinel.partition_number)

        cmd = ["Add-PartitionAccessPath", "-DiskNumber",
               mock.sentinel.disk_number,
               "-PartitionNumber", mock.sentinel.partition_number,
               "-AccessPath", mock.sentinel.quote_string]
        mock_quote_string.assert_called_once_with(mock.sentinel.mount_path)
        """mock_quote_string doesn't return the expected value"""
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_resize_partition(self):
        self._windows_utils.resize_partition(mock.sentinel.server,
                                             mock.sentinel.size_bytes,
                                             mock.sentinel.disk_number,
                                             mock.sentinel.partition_number)
        cmd = ['Resize-Partition', '-DiskNumber', mock.sentinel.disk_number,
               '-PartitionNumber', mock.sentinel.partition_number,
               '-Size', mock.sentinel.size_bytes]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def _test_get_disk_number_by_serial_number(self, out_value=None):
        mock_serial_number = "serial_number"
        self._remote_exec.return_value = (out_value, mock.sentinel.err)

        result = self._windows_utils.get_disk_number_by_serial_number(
            mock.sentinel.server,
            mock_serial_number)

        pattern = "%s*" % mock_serial_number[:15]
        cmd = ("Get-Disk | "
               "Where-Object {$_.SerialNumber -like '%s'} | "
               "Select-Object -ExpandProperty Number" % pattern)
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        if out_value:
            self.assertEqual(int(out_value), result)
        else:
            self.assertEqual(None, result)

    def test_get_disk_number_by_serial_number(self):
        _FAKE_DISK_NUMBER = "10"
        self._test_get_disk_number_by_serial_number(
            out_value=_FAKE_DISK_NUMBER)

    def test_get_disk_number_by_serial_number_invalid(self):
        self._test_get_disk_number_by_serial_number(out_value="")

    def _test_get_disk_number_by_mount_path(self, out_value=None):
        mock_mount_path = ""
        self._remote_exec.return_value = (out_value, mock.sentinel.err)

        result = self._windows_utils.get_disk_number_by_mount_path(
            mock.sentinel.server,
            mock_mount_path)

        cmd = ('Get-Partition | '
               'Where-Object {$_.AccessPaths -contains "%s"} | '
               'Select-Object -ExpandProperty DiskNumber' %
               (mock_mount_path + "\\"))
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        if out_value:
            self.assertEqual(int(out_value), result)
        else:
            self.assertEqual(None, result)

    def test_get_disk_number_by_mount_path(self):
        _FAKE_DISK_NUMBER = "10"
        self._test_get_disk_number_by_serial_number(
            out_value=_FAKE_DISK_NUMBER)

    def test_get_disk_number_by_mount_path_invalid(self):
        self._test_get_disk_number_by_serial_number(out_value="")

    @mock.patch.object(windows_utils.WindowsUtils, '_quote_string')
    def test_get_disk_size_by_path(self, mock_quote_string):
        _FAKE_DISK_SIZE = "1024"
        self._windows_utils._fsutil_total_space_regex = mock.MagicMock()
        self._windows_utils._fsutil_total_space_regex.findall.return_value = (
            _FAKE_DISK_SIZE)

        mock_quote_string.return_value = mock.sentinel.quote_string
        self._remote_exec.return_value = (_FAKE_DISK_SIZE,
                                          mock.sentinel.err)

        result = self._windows_utils.get_disk_size_by_path(
            mock.sentinel.server,
            mock.sentinel.mount_path)

        cmd = ["fsutil", "volume", "diskfree", mock.sentinel.quote_string]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        mock_quote_string.assert_called_once_with(mock.sentinel.mount_path)
        self.assertEqual(long(_FAKE_DISK_SIZE[1]), result)

    def test_get_partition_maximum_size(self):
        _FAKE_MAX_SIZE = "1024"
        self._remote_exec.return_value = (_FAKE_MAX_SIZE, mock.sentinel.err)

        result = self._windows_utils.get_partition_maximum_size(
            mock.sentinel.server,
            mock.sentinel.disk_number,
            mock.sentinel.partition_number)

        cmd = ('Get-PartitionSupportedSize -DiskNumber %(disk_number)s '
               '-PartitionNumber %(partition_number)s | '
               'Select-Object -ExpandProperty SizeMax' %
               dict(disk_number=mock.sentinel.disk_number,
                    partition_number=mock.sentinel.partition_number))
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(long(_FAKE_MAX_SIZE), result)

    def test_set_disk_online_status(self):
        online = True
        self._windows_utils.set_disk_online_status(mock.sentinel.server,
                                                   mock.sentinel.disk_number,
                                                   online=online)

        cmd = ["Set-Disk", "-Number", mock.sentinel.disk_number,
               "-IsOffline", int(not online)]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_set_disk_readonly_status(self):
        self._windows_utils.set_disk_readonly_status(mock.sentinel.server,
                                                     mock.sentinel.disk_number,
                                                     readonly=False)
        cmd = ["Set-Disk", "-Number", mock.sentinel.disk_number,
               "-IsReadOnly", 0]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_update_disk(self):
        self._windows_utils.update_disk(mock.sentinel.server,
                                        mock.sentinel.disk_number)

        cmd = ["Update-Disk", mock.sentinel.disk_number]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_join_domain(self):
        mock_server = {'ip': mock.sentinel.server_ip}

        self._windows_utils.join_domain(mock_server,
                                        mock.sentinel.domain,
                                        mock.sentinel.admin_username,
                                        mock.sentinel.admin_password)

        cmds = [
            ('$password = "%s" | '
             'ConvertTo-SecureString -asPlainText -Force' %
             mock.sentinel.admin_password),
            ('$credential = '
             'New-Object System.Management.Automation.PSCredential('
             '"%s", $password)' % mock.sentinel.admin_username),
            ('Add-Computer -DomainName "%s" -Credential $credential' %
             mock.sentinel.domain)]
        cmd = ";".join(cmds)
        self._remote_exec.assert_called_once_with(mock_server, cmd)

    def test_unjoin_domain(self):
        self._windows_utils.unjoin_domain(mock.sentinel.server,
                                          mock.sentinel.admin_username,
                                          mock.sentinel.admin_password)

        cmds = [
            ('$password = "%s" | '
             'ConvertTo-SecureString -asPlainText -Force' %
             mock.sentinel.admin_password),
            ('$credential = '
             'New-Object System.Management.Automation.PSCredential('
             '"%s", $password)' % mock.sentinel.admin_username),
            ('Remove-Computer -UnjoinDomaincredential $credential '
             '-Passthru -Verbose -Force')]
        cmd = ";".join(cmds)
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_get_current_domain(self):
        _FAKE_DOMAIN = "domain"
        self._remote_exec.return_value = (_FAKE_DOMAIN, mock.sentinel.err)

        result = self._windows_utils.get_current_domain(mock.sentinel.server)

        cmd = "(Get-WmiObject Win32_ComputerSystem).Domain"
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(_FAKE_DOMAIN.strip(), result)

    @mock.patch.object(windows_utils.WindowsUtils, '_quote_string')
    def test_ensure_directory_exists(self, mock_quote_string):
        mock_quote_string.return_value = mock.sentinel.quote_string

        self._windows_utils.ensure_directory_exists(mock.sentinel.server,
                                                    mock.sentinel.path)

        cmd = ["New-Item", "-ItemType", "Directory",
               "-Force", "-Path", mock.sentinel.quote_string]
        mock_quote_string.assert_called_once_with(mock.sentinel.path)
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @mock.patch.object(windows_utils.WindowsUtils, 'path_exists')
    @mock.patch.object(windows_utils.WindowsUtils, '_quote_string')
    def _test_remove(self, mock_quote_string, mock_path_exists,
                     is_junction=False):
        mock_quote_string.return_value = mock.sentinel.quote_string
        mock_path_exists.return_value = mock.sentinel.path_exists

        self._windows_utils.remove(mock.sentinel.server,
                                   mock.sentinel.path,
                                   is_junction=is_junction)

        mock_quote_string.assert_called_once_with(mock.sentinel.path)
        if is_junction:
            cmd = ('[System.IO.Directory]::Delete('
                   '%(path)s, %(recurse)d)'
                   % dict(path=mock.sentinel.quote_string,
                          recurse=False))
        else:
            cmd = ["Remove-Item", "-Confirm:$false",
                   "-Path", mock.sentinel.quote_string, '-Force']

        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_remove(self):
        self._test_remove()

    def test_remove_with_junction(self):
        self._test_remove(is_junction=True)

    def _test_path_exists(self, path_exists=True):
        _FAKE_RESPONSE = "True" if path_exists else "False"
        self._remote_exec.return_value = (_FAKE_RESPONSE, mock.sentinel.err)

        result = self._windows_utils.path_exists(mock.sentinel.server,
                                                 mock.sentinel.path)

        cmd = ["Test-Path", mock.sentinel.path]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(_FAKE_RESPONSE == "True", result)

    def test_path_exists(self):
        self._test_path_exists()

    def test_path_does_not_exist(self):
        self._test_path_exists(path_exists=False)

    def test_normalize_path(self):
        result = self._windows_utils.normalize_path("C:/")

        self.assertEqual("C:\\", result)

    def test_get_interface_index_by_ip(self):
        _FAKE_INDEX = "2"
        self._remote_exec.return_value = (_FAKE_INDEX, mock.sentinel.err)

        result = self._windows_utils.get_interface_index_by_ip(
            mock.sentinel.server,
            mock.sentinel.ip)

        cmd = ('Get-NetIPAddress | '
               'Where-Object {$_.IPAddress -eq "%(ip)s"} | '
               'Select-Object -ExpandProperty InterfaceIndex' %
               dict(ip=mock.sentinel.ip))
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)
        self.assertEqual(int(_FAKE_INDEX), result)

    def test_set_dns_client_search_list(self):
        mock_search_list = ["A", "B", "C"]

        self._windows_utils.set_dns_client_search_list(mock.sentinel.server,
                                                       mock_search_list)

        cmd = ["Set-DnsClientGlobalSetting",
               "-SuffixSearchList", "@('A','B','C')"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    def test_set_dns_client_server_addresses(self):
        mock_dns_servers = ["A", "B", "C"]

        self._windows_utils.set_dns_client_server_addresses(
            mock.sentinel.server,
            mock.sentinel.if_index,
            mock_dns_servers)

        cmd = ["Set-DnsClientServerAddress",
               "-InterfaceIndex", mock.sentinel.if_index,
               "-ServerAddresses", "('A','B','C')"]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @mock.patch.object(windows_utils.WindowsUtils, '_quote_string')
    def test_set_win_reg_value(self, mock_quote_string):
        mock_quote_string.return_value = mock.sentinel.quote_string

        self._windows_utils.set_win_reg_value(mock.sentinel.server,
                                              mock.sentinel.path,
                                              mock.sentinel.key,
                                              mock.sentinel.value)

        mock_quote_string.assert_called_once_with(mock.sentinel.path)
        cmd = ['Set-ItemProperty', '-Path', mock.sentinel.quote_string,
               '-Name', mock.sentinel.key, '-Value', mock.sentinel.value]
        self._remote_exec.assert_called_once_with(mock.sentinel.server, cmd)

    @mock.patch.object(windows_utils.WindowsUtils, '_quote_string')
    def _test_get_win_reg_value(self, mock_quote_string, name=None):
        mock_quote_string.return_value = mock.sentinel.quote_string
        self._remote_exec.return_value = ["A", "B"]

        result = self._windows_utils.get_win_reg_value(mock.sentinel.server,
                                                       mock.sentinel.path,
                                                       name=name)

        cmd = "Get-ItemProperty -Path %s" % mock.sentinel.quote_string
        if name:
            cmd += " | Select-Object -ExpandProperty %s" % name
        self._remote_exec.assert_called_once_with(mock.sentinel.server,
                                                  cmd,
                                                  retry=False)
        self.assertEqual("A", result)

    def test_get_win_reg_value(self):
        self._test_get_win_reg_value()

    def test_get_win_reg_value_with_name(self):
        self._test_get_win_reg_value(name=mock.sentinel.mame)

    def test_quote_string(self):
        result = self._windows_utils._quote_string(mock.sentinel.string)

        self.assertEqual('"%s"' % mock.sentinel.string, result)
