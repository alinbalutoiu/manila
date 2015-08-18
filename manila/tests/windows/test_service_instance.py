import os

from manila import exception
from manila.share.configuration import Configuration
from manila.share.drivers import service_instance as generic_service_instance
from manila.share.drivers.windows import service_instance
from manila.share.drivers.windows import windows_utils
from manila import test
import mock
from oslo_concurrency import processutils
from oslo_config import cfg

CONF = cfg.CONF
CONF.import_opt('driver_handles_share_servers',
                'manila.share.driver')
CONF.register_opts(generic_service_instance.common_opts)
service_manager = service_instance.WindowsServiceInstanceManager


class WindowsServiceInstanceManagerTestCase(test.TestCase):
    @mock.patch.object(windows_utils, 'WindowsUtils')
    @mock.patch.object(service_manager, '_check_auth_mode')
    def setUp(self, mock_check_auth, mock_utils_cls):
        self.fake_conf = Configuration(None)
        self.flags(service_instance_user=mock.sentinel.username)
        self._remote_execute = mock.MagicMock()

        self._service_instance = (
            service_instance.WindowsServiceInstanceManager(
                remote_execute=self._remote_execute,
                driver_config=self.fake_conf))
        self._windows_utils = mock_utils_cls.return_value
        super(WindowsServiceInstanceManagerTestCase, self).setUp()

    @mock.patch('os.path.exists')
    @mock.patch.object(service_manager, '_check_password_complexity')
    def _test_check_auth_mode(self, mock_complexity, mock_path_exists,
                              expected_exception=False, use_cert_auth=True):
        self._service_instance._cert_pem_path = mock.sentinel.cert
        self._service_instance._cert_key_pem_path = mock.sentinel.key

        if use_cert_auth:
            self._service_instance._use_cert_auth = True
            if expected_exception:
                mock_path_exists.return_value = False
                self.assertRaises(exception.ServiceInstanceException,
                                  self._service_instance._check_auth_mode)

                mock_path_exists.assert_called_once_with(
                    mock.sentinel.cert)
            else:
                mock_path_exists.return_value = True
                self._service_instance._check_auth_mode()

                mock_path_exists.assert_has_calls(
                    [mock.call(mock.sentinel.cert),
                     mock.call(mock.sentinel.key)])
        else:
            self._service_instance._use_cert_auth = False
            self.flags(service_instance_password=mock.sentinel.password)
            if expected_exception:
                mock_complexity.return_value = False

                self.assertRaises(exception.ServiceInstanceException,
                                  self._service_instance._check_auth_mode)
            else:
                mock_complexity.return_value = True
                self._service_instance._check_auth_mode()
            mock_complexity.assert_called_once_with(mock.sentinel.password)

    def test_check_auth_mode_with_cert(self):
        self._test_check_auth_mode()

    def test_check_auth_mode_with_cert_exception(self):
        self._test_check_auth_mode(expected_exception=True)

    def test_check_auth_mode_without_cert(self):
        self._test_check_auth_mode(use_cert_auth=False)

    def test_check_auth_mode_without_cert_exception(self):
        self._test_check_auth_mode(expected_exception=True,
                                   use_cert_auth=False)

    def _test_get_auth_info(self, use_cert_auth=True):
        self._service_instance._use_cert_auth = use_cert_auth
        self._service_instance._cert_pem_path = mock.sentinel.cert
        self._service_instance._cert_key_pem_path = mock.sentinel.key

        result = self._service_instance._get_auth_info()

        expected_result = {'use_cert_auth': use_cert_auth}
        if use_cert_auth:
            expected_result.update(cert_pem_path=mock.sentinel.cert,
                                   cert_key_pem_path=mock.sentinel.key)

        self.assertEqual(expected_result, result)

    def test_get_auth_info_with_cert(self):
        self._test_get_auth_info()

    def test_get_auth_info_without_cert(self):
        self._test_get_auth_info(use_cert_auth=False)

    @mock.patch.object(service_manager, '_get_auth_info')
    @mock.patch.object(generic_service_instance.ServiceInstanceManager,
                       'get_common_server')
    def test_common_server(self, mock_get_server, mock_get_auth):
        mock_data = {'backend_details': {}}
        mock_auth = {'auth_info': mock.sentinel.auth}

        mock_get_server.return_value = mock_data
        mock_get_auth.return_value = mock_auth

        result = self._service_instance.get_common_server()

        mock_get_server.assert_called_once_with()
        expected_result = {'backend_details': {
                           'auth_info': mock.sentinel.auth}
                           }
        self.assertEqual(expected_result, result)

    @mock.patch.object(service_manager, '_get_auth_info')
    @mock.patch.object(generic_service_instance.ServiceInstanceManager,
                       '_get_new_instance_details')
    def test_get_new_instance_details(self, mock_get_details, mock_get_auth):
        mock_get_details.return_value = {}
        mock_get_auth.return_value = {'auth_info': mock.sentinel.auth}

        result = self._service_instance._get_new_instance_details(
            server=mock.sentinel.server)

        mock_get_details.assert_called_once_with(mock.sentinel.server)
        self.assertEqual({'auth_info': mock.sentinel.auth}, result)

    def test_check_password_strong(self):
        check_pass = self._service_instance._check_password_complexity
        self.assertTrue(check_pass(password='abAB01'))

    def test_check_password_weak(self):
        check_pass = self._service_instance._check_password_complexity
        self.assertFalse(check_pass(password='abcdef'))

    def test_check_password_length_too_short(self):
        check_pass = self._service_instance._check_password_complexity
        self.assertFalse(check_pass(password='a'))

    def _test_test_server_connection(self, side_effect=None,
                                     expected_exception=False):
        mock_server = {'ip': mock.sentinel.ip}
        self._remote_execute.side_effect = side_effect

        if expected_exception:
            self._service_instance._test_server_connection(mock_server)
        else:
            self.assertTrue(self._service_instance._test_server_connection(
                mock_server))

        self._remote_execute.assert_called_once_with(mock_server,
                                                     "whoami",
                                                     retry=False)

    def test_server_connection(self):
        self._test_test_server_connection()

    def test_server_connection_with_exception(self):
        self._test_test_server_connection(side_effect=Exception,
                                          expected_exception=True)

    def _test_get_service_instance_create_kwargs(self, use_cert_auth=True):
        self._service_instance._use_cert_auth = use_cert_auth
        self.flags(service_instance_password='admin_pass')

        # with mock.patch.object(builtins, 'open',
        #                        mock.mock_open(read_data='test')):
        #     result = self._get_service_instance_create_kwargs()

        # if use_cert_auth:
        #     expected_result = {'user_data': 'test'}
        # else:
        #     result = self._get_service_instance_create_kwargs()

    def test_get_service_instance_create_kwargs(self):
        self._test_get_service_instance_create_kwargs()

    def test_get_service_instance_create_kwargs_without_cert(self):
        self._test_get_service_instance_create_kwargs(use_cert_auth=False)

    @mock.patch.object(generic_service_instance.ServiceInstanceManager,
                       'set_up_service_instance')
    @mock.patch.object(service_manager, 'get_valid_security_service')
    @mock.patch.object(service_manager, '_setup_security_service')
    def _test_set_up_service_instance(self, mock_setup_security_service,
                                      mock_get_valid_security_service,
                                      mock_setup_service_instance,
                                      valid_security_service=None):
        mock_service_instance = {'instance_details': None}
        mock_network_info = {'security_services':
                             mock.sentinel.security_services}

        mock_setup_service_instance.return_value = mock_service_instance
        mock_get_valid_security_service.return_value = valid_security_service

        result = self._service_instance.set_up_service_instance(
            mock.sentinel.context, mock_network_info)

        # NOTE(abalutoiu): this is the super class method
        mock_setup_service_instance.assert_called_once_with(
            mock.sentinel.context, mock_network_info)
        mock_get_valid_security_service.assert_called_once_with(
            mock.sentinel.security_services)

        if valid_security_service:
            mock_setup_security_service.assert_called_once_with(
                mock_service_instance, valid_security_service)

        mock_service_instance['joined_domain'] = bool(valid_security_service)
        self.assertEqual(mock_service_instance, result)

    def test_set_up_service_instance(self):
        self._test_set_up_service_instance()

    def test_set_up_service_instance_invalid_security(self):
        self._test_set_up_service_instance(
            valid_security_service=mock.sentinel.valid_security_service)

    @mock.patch.object(service_manager,
                       '_run_cloudbase_init_plugin_after_reboot')
    @mock.patch.object(generic_service_instance.ServiceInstanceManager,
                       'reboot_server')
    @mock.patch.object(generic_service_instance.ServiceInstanceManager,
                       'wait_for_instance_to_be_active')
    @mock.patch.object(generic_service_instance.ServiceInstanceManager,
                       '_check_server_availability')
    def _test_setup_security_service(self, mock_check_availability,
                                     mock_wait_instance_active,
                                     mock_reboot_server,
                                     mock_cloudbase_init_plugin,
                                     expected_exception=None,
                                     server_available=True,
                                     domain_mismatch=False,
                                     fails_join_domain=False):
        mock_security_service = {'domain': mock.sentinel.domain,
                                 'user': mock.sentinel.user,
                                 'password': mock.sentinel.password,
                                 'dns_ip': mock.sentinel.ip}
        mock_server = {'ip': mock.sentinel.ip,
                       'instance_id': mock.sentinel.id}
        self.flags(max_time_to_build_instance=10)

        self._windows_utils.set_dns_client_search_list.return_value = (
            mock.sentinel.dns_list_result)
        self._windows_utils.get_interface_index_by_ip.return_value = (
            mock.sentinel.interface_index)
        self._windows_utils.set_dns_client_server_addresses.return_value = (
            mock.sentinel.dns_client_server_addresses)
        self._windows_utils.join_domain.side_effect = expected_exception

        mock_check_availability.return_value = server_available
        self._windows_utils.get_current_domain.return_value = (
            None if domain_mismatch else mock.sentinel.domain)

        if not server_available or domain_mismatch or fails_join_domain:
            self.assertRaises(expected_exception,
                              self._service_instance._setup_security_service,
                              mock_server,
                              mock_security_service)
        else:
            self._service_instance._setup_security_service(
                mock_server, mock_security_service)
            self._windows_utils.get_current_domain.assert_called_once_with(
                mock_server)
            mock_reboot_server.assert_called_once_with(
                mock_server, soft_reboot=True)
            mock_wait_instance_active.assert_called_once_with(
                mock_server['instance_id'],
                timeout=self._service_instance.max_time_to_build_instance)
            mock_check_availability.assert_called_once_with(mock_server)

        utils = self._windows_utils
        utils.set_dns_client_search_list.assert_called_once_with(
            mock_server, [mock_security_service['domain']])
        utils.get_interface_index_by_ip.assert_called_once_with(
            mock_server, mock_server['ip'])
        utils.set_dns_client_server_addresses.assert_called_once_with(
            mock_server,
            mock.sentinel.interface_index,
            [mock_security_service['dns_ip']])

        mock_cloudbase_init_plugin.assert_called_once_with(
            mock_server,
            plugin_name=self._service_instance._CBS_INIT_WINRM_PLUGIN)
        utils.join_domain.assert_called_once_with(
            mock_server,
            mock_security_service['domain'],
            mock_security_service['user'],
            mock_security_service['password'])

    def test_setup_security_service(self):
        self._test_setup_security_service()

    def test_setup_security_service_fails_join_domain(self):
        self._test_setup_security_service(
            expected_exception=processutils.ProcessExecutionError,
            fails_join_domain=True)

    def test_setup_security_service_server_unavailable(self):
        self._test_setup_security_service(
            expected_exception=exception.ServiceInstanceException,
            server_available=False)

    def test_setup_security_service_domain_mismatch(self):
        self._test_setup_security_service(
            expected_exception=exception.ServiceInstanceException,
            domain_mismatch=True)

    def _test_get_valid_security_service(self, security_services=None):
        result = self._service_instance.get_valid_security_service(
            security_services)

        if (security_services and
                security_services[0]['type'] == 'active_directory'):
            self.assertEqual(security_services[0], result)
        else:
            self.assertEqual(None, result)

    def test_get_valid_security_service_with_ad(self):
        security_services = [{'type': 'active_directory'}]
        self._test_get_valid_security_service(security_services)

    def test_get_valid_security_service_without_ad(self):
        security_services = [{'type': mock.sentinel.type}]
        self._test_get_valid_security_service(security_services)

    def test_get_invalid_security_service(self):
        self._test_get_valid_security_service()

    def test_get_multiple_security_service(self):
        security_services = [{'type': mock.sentinel.type},
                             {'another_type': mock.sentinel.another_type}]
        self._test_get_valid_security_service(security_services)

    @mock.patch.object(service_manager, '_get_cbs_init_reg_section')
    def test_run_cloudbase_init_plugin_after_reboot(self, mock_cbs_init_reg):
        mock_server = {'instance_id': mock.sentinel.instance_id}
        mock_cbs_init_reg.return_value = mock.sentinel.cbs_init_reg
        mock_plugin_key_path = "%(cbs_init)s\\%(instance_id)s\\Plugins" % {
            'cbs_init': mock.sentinel.cbs_init_reg,
            'instance_id': mock_server['instance_id']}

        self._service_instance._run_cloudbase_init_plugin_after_reboot(
            server=mock_server,
            plugin_name=mock.sentinel.plugin_name)

        mock_cbs_init_reg.assert_called_once_with(mock_server)
        self._windows_utils.set_win_reg_value.assert_called_once_with(
            mock_server,
            path=mock_plugin_key_path,
            key=mock.sentinel.plugin_name,
            value=self._service_instance._CBS_INIT_RUN_PLUGIN_AFTER_REBOOT)

    def _test_get_cbs_init_reg_section(self, side_effect=None,
                                       expected_exception=None):
        self._windows_utils.normalize_path.return_value = (
            mock.sentinel.normalized_path)
        self._windows_utils.get_win_reg_value.side_effect = side_effect

        if expected_exception is not None:
            self.assertRaises(expected_exception,
                              self._service_instance._get_cbs_init_reg_section,
                              mock.sentinel.server)
        else:
            self._service_instance._get_cbs_init_reg_section(
                mock.sentinel.server)

        mock_base_path = 'hklm:\\SOFTWARE'
        mock_cbs_section = 'Cloudbase Solutions\\Cloudbase-Init'
        mock_upper_sections = ['', 'Wow6432Node']
        first_call = os.path.join(mock_base_path,
                                  mock_upper_sections[0],
                                  mock_cbs_section)
        second_call = os.path.join(mock_base_path,
                                   mock_upper_sections[1],
                                   mock_cbs_section)
        self._windows_utils.normalize_path.assert_has_calls(
            [mock.call(first_call), mock.call(second_call)])

    def test_get_cbs_init_reg_section_with_success(self):
        error = processutils.ProcessExecutionError(stderr='Cannot find path')
        self._test_get_cbs_init_reg_section(
            side_effect=(error, None))

    def test_could_not_retrieve_cbs_init_reg_section(self):
        error = processutils.ProcessExecutionError(stderr='Cannot find path')
        self._test_get_cbs_init_reg_section(
            side_effect=(error, error),
            expected_exception=exception.ServiceInstanceException)

    def test_path_not_found_cbd_init_reg_section(self):
        error = processutils.ProcessExecutionError
        self._test_get_cbs_init_reg_section(
            side_effect=(error(stderr='Cannot find path'),
                         error(stderr='')),
            expected_exception=processutils.ProcessExecutionError)
