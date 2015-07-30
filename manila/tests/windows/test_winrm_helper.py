import mock

from manila import test
from manila.share.drivers.windows import winrm_helper


class WinRMHelperTestCase(test.TestCase):
    _FAKE_SERVER = {'ip': mock.sentinel.ip}

    def setUp(self):
        self._winrm = winrm_helper.WinRMHelper()
        super(WinRMHelperTestCase, self).setUp()

    @mock.patch.object(winrm_helper.WinRMHelper, '_get_auth')
    @mock.patch.object(winrm_helper, 'WinRMConnection')
    def test_get_conn(self, mock_conn_cls, mock_get_auth):
        mock_auth = {'mock_auth_key': mock.sentinel.auth_opt}
        mock_get_auth.return_value = mock_auth

        conn = self._winrm._get_conn(self._FAKE_SERVER)

        mock_get_auth.assert_called_once_with(self._FAKE_SERVER)
        mock_conn_cls.assert_called_once_with(
            ip=self._FAKE_SERVER['ip'],
            conn_timeout=self._winrm._config.winrm_conn_timeout,
            operation_timeout=self._winrm._config.winrm_operation_timeout,
            **mock_auth
            )
        self.assertEquals(mock_conn_cls.return_value, conn)

    @mock.patch('time.sleep')
    @mock.patch.object(winrm_helper.WinRMHelper, '_get_conn')
    @mock.patch.object(winrm_helper.WinRMHelper, '_execute')
    def _test_execute(self, mock_execute, mock_get_conn, mock_sleep,
                      expected_call_count=1, retry=True, retry_count=1,
                      side_effect=None, expected_exception=None):
        self.flags(winrm_retry_count=retry_count)

        mock_execute.side_effect = side_effect

        if not expected_exception:
            result = self._winrm.execute(self._FAKE_SERVER,
                                         mock.sentinel.command,
                                         mock.sentinel.check_exit_code,
                                         retry=retry)
            self.assertEquals(mock.sentinel.result, result)
        else:
            self.assertRaises(expected_exception,
                              self._winrm.execute,
                              self._FAKE_SERVER,
                              mock.sentinel.command,
                              mock.sentinel.check_exit_code,
                              retry=retry)

        mock_get_conn.assert_called_once_with(self._FAKE_SERVER)
        mock_execute.assert_has_calls(
            [mock.call(mock_get_conn.return_value,
                       mock.sentinel.command,
                       mock.sentinel.check_exit_code)] * expected_call_count)
        mock_sleep.assert_has_calls(
            [mock.call(self._winrm._config.winrm_retry_interval)] *
            (expected_call_count - 1))

    def test_execute(self):
        side_effect = (mock.sentinel.result,)
        self._test_execute(side_effect=side_effect)

    def test_execute_exception_without_retry(self):
        self._test_execute(retry=False,
                           side_effect=Exception,
                           expected_exception=Exception)

    def test_execute_exception_after_retry(self):
        retry_count = 2
        self._test_execute(side_effect=Exception,
                           expected_exception=Exception,
                           retry_count=retry_count,
                           expected_call_count=retry_count + 1)

    def test_execute_success_after_retry(self):
        retry_count = 2
        side_effect = (Exception, mock.sentinel.result)
        self._test_execute(side_effect=side_effect,
                           expected_call_count=2,
                           retry_count=retry_count)

    @mock.patch('oslo_utils.strutils.mask_password')
    @mock.patch.object(winrm_helper.WinRMHelper, '_parse_command')
    def _test_execute_helper(self, mock_parse_command, mock_mask_password,
                             check_exit_code=True, exit_code=0):
        mock_parse_command.return_value = (mock.sentinel.cmd,
                                           mock.sentinel.sanitized_cmd)
        mock_conn = mock.Mock()
        mock_conn.execute.return_value = (mock.sentinel.stdout,
                                          mock.sentinel.stderr,
                                          exit_code)
        mock_mask_password.return_value = mock.sentinel.response

        if exit_code == 0 or not check_exit_code:
            result = self._winrm._execute(mock_conn,
                                          mock.sentinel.command,
                                          check_exit_code=check_exit_code)
            expected_result = (mock.sentinel.stdout, mock.sentinel.stderr)
            self.assertEquals(expected_result, result)
        else:
            self.assertRaises(Exception,
                              self._winrm._execute,
                              mock_conn,
                              mock.sentinel.command,
                              check_exit_code=check_exit_code)

        mock_parse_command.assert_called_once_with(mock.sentinel.command)
        mock_conn.execute.assert_called_once_with(mock.sentinel.cmd)
        mock_mask_password.assert_has_calls([mock.call(mock.sentinel.stdout),
                                            mock.call(mock.sentinel.stderr)])

    def test_execute_helper(self):
        self._test_execute_helper()

    def test_execute_helper_exception(self):
        self._test_execute_helper(exit_code=1)

    def test_execute_helper_exception_ignored(self):
        self._test_execute_helper(exit_code=1, check_exit_code=False)

    @mock.patch('base64.b64encode')
    @mock.patch('oslo_utils.strutils.mask_password')
    def test_parse_command(self, mock_mask_password, mock_base64):
        mock_mask_password.return_value = mock.sentinel.sanitized_cmd
        mock_base64.return_value = mock.sentinel.encoded_string

        cmd = ('Get-Disk', '-Number', 1)
        result = self._winrm._parse_command(cmd)

        new_cmd = 'Get-Disk -Number 1'
        mock_mask_password.assert_called_once_with(new_cmd)

        command = ("powershell.exe -ExecutionPolicy RemoteSigned "
                   "-NonInteractive -EncodedCommand %s" %
                   mock.sentinel.encoded_string)
        expected_result = command, mock.sentinel.sanitized_cmd
        mock_base64.assert_called_once_with(new_cmd.encode("utf_16_le"))
        self.assertEquals(expected_result, result)

    def _test_get_auth(self, use_cert_auth=False):
        mock_server = {'use_cert_auth': use_cert_auth,
                       'cert_pem_path': mock.sentinel.path,
                       'cert_key_pem_path': mock.sentinel.key_path,
                       'username': mock.sentinel.username,
                       'password': mock.sentinel.password
                       }

        result = self._winrm._get_auth(mock_server)

        expected_result = {'username': mock_server['username']}
        if use_cert_auth:
            expected_result['cert_pem_path'] = mock_server['cert_pem_path']
            expected_result['cert_key_pem_path'] = mock_server[
                                                        'cert_key_pem_path']
        else:
            expected_result['password'] = mock_server['password']

        self.assertEquals(expected_result, result)

    def test_get_auth_with_certificate(self):
        self._test_get_auth(use_cert_auth=True)

    def test_get_auth_with_password(self):
        self._test_get_auth()


class WinRMConnectionTestCase(test.TestCase):
    _DEFAULT_PORT_HTTP = 5985
    _DEFAULT_PORT_HTTPS = 5986

    @mock.patch('winrm.protocol.Protocol')
    @mock.patch.object(winrm_helper.WinRMConnection, '_get_url')
    @mock.patch.object(winrm_helper.WinRMConnection, '_get_default_port')
    def setUp(self, mock_port, mock_url, mock_protocol_cls):
        self._winrm = winrm_helper.WinRMConnection()
        self._mock_conn = mock_protocol_cls.return_value
        super(WinRMConnectionTestCase, self).setUp()

    def _test_get_default_port(self, use_ssl=True):
        port = self._winrm._get_default_port(use_ssl=use_ssl)
        if use_ssl:
            self.assertEquals(self._DEFAULT_PORT_HTTPS, port)
        else:
            self.assertEquals(self._DEFAULT_PORT_HTTP, port)

    def test_get_port_https(self):
        self._test_get_default_port()

    def test_get_port_http(self):
        self._test_get_default_port(use_ssl=False)

    def _test_get_url(self, ip=None, use_ssl=True):
        if not ip:
            self.assertRaises(Exception,
                              self._winrm._get_url,
                              ip=ip,
                              port=self._DEFAULT_PORT_HTTP,
                              use_ssl=use_ssl)
        else:
            port = (self._DEFAULT_PORT_HTTPS
                    if use_ssl else self._DEFAULT_PORT_HTTP)
            result = self._winrm._get_url(ip=ip,
                                          port=port,
                                          use_ssl=use_ssl)

            protocol = 'https' if use_ssl else 'http'
            expected_result = '%(protocol)s://%(ip)s:%(port)s/wsman' % {
                'protocol': protocol, 'ip': ip, 'port': port}
            self.assertEquals(expected_result, result)

    def test_get_url_with_ssl(self):
        self._test_get_url(ip='8.8.8.8')

    def test_get_url_without_ssl(self):
        self._test_get_url(ip='8.8.8.8', use_ssl=False)

    def test_get_url_exception(self):
        self._test_get_url()

    def _test_execute(self, success_cmd=True, opened_shell=True):
        self._mock_conn.open_shell.return_value = mock.sentinel.shell_id
        self._mock_conn.run_command.return_value = mock.sentinel.cmd_id
        expected_result = (mock.sentinel.output,) * 3
        self._mock_conn.get_command_output.return_value = (expected_result)

        result = self._winrm.execute(mock.sentinel.cmd)

        self._mock_conn.open_shell.assert_called_once_with()
        self._mock_conn.run_command.assert_called_once_with(
            mock.sentinel.shell_id, mock.sentinel.cmd)

        if success_cmd:
            self._mock_conn.cleanup_command.assert_called_once_with(
                mock.sentinel.shell_id, mock.sentinel.cmd_id)
        if opened_shell:
            self._mock_conn.close_shell.assert_called_once_with(
                mock.sentinel.shell_id)

        self.assertEquals(expected_result, result)

    def test_execute(self):
        self._test_execute()

    def test_execute_fail_cmd(self):
        self._test_execute(success_cmd=False)

    def test_execute_no_shell(self):
        self._test_execute(opened_shell=False)
