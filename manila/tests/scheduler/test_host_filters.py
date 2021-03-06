# Copyright 2011 OpenStack LLC.  # All Rights Reserved.
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
Tests For Scheduler Host Filters.
"""

import ddt
from oslo_serialization import jsonutils

from manila import context
from manila.openstack.common.scheduler import filters
from manila import test
from manila.tests.scheduler import fakes
from manila import utils


@ddt.ddt
class HostFiltersTestCase(test.TestCase):
    """Test case for host filters."""

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.context = context.RequestContext('fake', 'fake')
        self.json_query = jsonutils.dumps(
            ['and', ['>=', '$free_capacity_gb', 1024],
             ['>=', '$total_capacity_gb', 10 * 1024]])
        # This has a side effect of testing 'get_filter_classes'
        # when specifying a method (in this case, our standard filters)
        filter_handler = filters.HostFilterHandler('manila.scheduler.filters')
        classes = filter_handler.get_all_classes()
        self.class_map = {}
        for cls in classes:
            self.class_map[cls.__name__] = cls

    def _stub_service_is_up(self, ret_value):
        def fake_service_is_up(service):
            return ret_value
        self.mock_object(utils, 'service_is_up', fake_service_is_up)

    @ddt.data(
        {'size': 100, 'share_on': None, 'host': 'host1'},
        {'size': 100, 'share_on': 'host1#pool1', 'host': 'host1#pools1'})
    @ddt.unpack
    def test_capacity_filter_passes(self, size, share_on, host):
        self._stub_service_is_up(True)
        filt_cls = self.class_map['CapacityFilter']()
        filter_properties = {'size': size,
                             'share_exists_on': share_on}
        service = {'disabled': False}
        host = fakes.FakeHostState(host,
                                   {'total_capacity_gb': 500,
                                    'free_capacity_gb': 200,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(filt_cls.host_passes(host, filter_properties))

    @ddt.data(
        {'free_capacity': 120, 'total_capacity': 200,
         'reserved': 20},
        {'free_capacity': None, 'total_capacity': None,
         'reserved': None})
    @ddt.unpack
    def test_capacity_filter_fails(self, free_capacity, total_capacity,
                                   reserved):
        self._stub_service_is_up(True)
        filt_cls = self.class_map['CapacityFilter']()
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'total_capacity_gb': total_capacity,
                                    'free_capacity_gb': free_capacity,
                                    'reserved_percentage': reserved,
                                    'updated_at': None,
                                    'service': service})
        self.assertFalse(filt_cls.host_passes(host, filter_properties))

    @ddt.data('infinite', 'unknown')
    def test_capacity_filter_passes_infinite_unknown(self, free):
        self._stub_service_is_up(True)
        filt_cls = self.class_map['CapacityFilter']()
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'free_capacity_gb': free,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(filt_cls.host_passes(host, filter_properties))

    @ddt.data(
        {'free_capacity': 'infinite', 'total_capacity': 'infinite'},
        {'free_capacity': 'unknown', 'total_capacity': 'unknown'})
    @ddt.unpack
    def test_capacity_filter_passes_total(self, free_capacity,
                                          total_capacity):
        self._stub_service_is_up(True)
        filt_cls = self.class_map['CapacityFilter']()
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'free_capacity_gb': free_capacity,
                                    'total_capacity_gb': total_capacity,
                                    'reserved_percentage': 0,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(filt_cls.host_passes(host, filter_properties))

    @ddt.data('infinite', 'unknown', 0)
    def test_capacity_filter_fails_total(self, total):
        self._stub_service_is_up(True)
        filt_cls = self.class_map['CapacityFilter']()
        filter_properties = {'size': 100}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'total_capacity_gb': total,
                                    'reserved_percentage': 5,
                                    'updated_at': None,
                                    'service': service})
        self.assertFalse(filt_cls.host_passes(host, filter_properties))

    @ddt.data(
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 200, 'provisioned': 500,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': False},
        {'size': 3000, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 200, 'provisioned': 7000,
         'max_ratio': 20, 'reserved': 5, 'thin_prov': True,
         'thick_prov': False},
        {'size': 100, 'cap_thin': '<is> False', 'cap_thick': '<is> True',
         'total': 500, 'free': 200, 'provisioned': 300,
         'max_ratio': 1.0, 'reserved': 5, 'thin_prov': False,
         'thick_prov': True},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 200, 'provisioned': 400,
         'max_ratio': 1.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': False},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> True',
         'total': 500, 'free': 125, 'provisioned': 400,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': True},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 80, 'provisioned': 600,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': False},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> True',
         'total': 500, 'free': 100, 'provisioned': 400,
         'max_ratio': 2.0, 'reserved': 0, 'thin_prov': True,
         'thick_prov': True})
    @ddt.unpack
    def test_filter_thin_thick_passes(self, size, cap_thin, cap_thick,
                                      total, free, provisioned, max_ratio,
                                      reserved, thin_prov, thick_prov):
        self._stub_service_is_up(True)
        filt_cls = self.class_map['CapacityFilter']()
        filter_properties = {'size': size,
                             'capabilities:thin_provisioning_support':
                                 cap_thin,
                             'capabilities:thick_provisioning_support':
                                 cap_thick}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'total_capacity_gb': total,
                                    'free_capacity_gb': free,
                                    'provisioned_capacity_gb': provisioned,
                                    'max_over_subscription_ratio': max_ratio,
                                    'reserved_percentage': reserved,
                                    'thin_provisioning_support': thin_prov,
                                    'thick_provisioning_support': thick_prov,
                                    'updated_at': None,
                                    'service': service})
        self.assertTrue(filt_cls.host_passes(host, filter_properties))

    @ddt.data(
        {'size': 200, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 100, 'provisioned': 400,
         'max_ratio': 0.8, 'reserved': 0, 'thin_prov': True,
         'thick_prov': False},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 200, 'provisioned': 700,
         'max_ratio': 1.5, 'reserved': 5, 'thin_prov': True,
         'thick_prov': False},
        {'size': 2000, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 30, 'provisioned': 9000,
         'max_ratio': 20.0, 'reserved': 0, 'thin_prov': True,
         'thick_prov': False},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 100, 'provisioned': 1000,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': False},
        {'size': 100, 'cap_thin': '<is> False', 'cap_thick': '<is> True',
         'total': 500, 'free': 100, 'provisioned': 400,
         'max_ratio': 1.0, 'reserved': 5, 'thin_prov': False,
         'thick_prov': True},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> True',
         'total': 500, 'free': 0, 'provisioned': 800,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': True},
        {'size': 100, 'cap_thin': '<is> True', 'cap_thick': '<is> True',
         'total': 500, 'free': 99, 'provisioned': 1000,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': True},
        {'size': 400, 'cap_thin': '<is> True', 'cap_thick': '<is> False',
         'total': 500, 'free': 200, 'provisioned': 600,
         'max_ratio': 2.0, 'reserved': 5, 'thin_prov': True,
         'thick_prov': False})
    @ddt.unpack
    def test_filter_thin_thick_fails(self, size, cap_thin, cap_thick,
                                     total, free, provisioned, max_ratio,
                                     reserved, thin_prov, thick_prov):
        self._stub_service_is_up(True)
        filt_cls = self.class_map['CapacityFilter']()
        filter_properties = {'size': size,
                             'capabilities:thin_provisioning_support':
                                 cap_thin,
                             'capabilities:thick_provisioning_support':
                                 cap_thick}
        service = {'disabled': False}
        host = fakes.FakeHostState('host1',
                                   {'total_capacity_gb': total,
                                    'free_capacity_gb': free,
                                    'provisioned_capacity_gb': provisioned,
                                    'max_over_subscription_ratio': max_ratio,
                                    'reserved_percentage': reserved,
                                    'thin_provisioning_support': thin_prov,
                                    'thick_provisioning_support': thick_prov,
                                    'updated_at': None,
                                    'service': service})
        self.assertFalse(filt_cls.host_passes(host, filter_properties))

    def test_retry_filter_disabled(self):
        # Test case where retry/re-scheduling is disabled.
        filt_cls = self.class_map['RetryFilter']()
        host = fakes.FakeHostState('host1', {})
        filter_properties = {}
        self.assertTrue(filt_cls.host_passes(host, filter_properties))

    def test_retry_filter_pass(self):
        # Node not previously tried.
        filt_cls = self.class_map['RetryFilter']()
        host = fakes.FakeHostState('host1', {})
        retry = dict(num_attempts=2, hosts=['host2'])
        filter_properties = dict(retry=retry)
        self.assertTrue(filt_cls.host_passes(host, filter_properties))

    def test_retry_filter_fail(self):
        # Node was already tried.
        filt_cls = self.class_map['RetryFilter']()
        host = fakes.FakeHostState('host1', {})
        retry = dict(num_attempts=1, hosts=['host1'])
        filter_properties = dict(retry=retry)
        self.assertFalse(filt_cls.host_passes(host, filter_properties))
