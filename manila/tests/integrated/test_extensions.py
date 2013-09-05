# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Justin Santa Barbara
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

from manila import flags
from manila.openstack.common import log as logging
from manila.tests.integrated import integrated_helpers


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)


class ExtensionsTest(integrated_helpers._IntegratedTestBase):
    def _get_flags(self):
        f = super(ExtensionsTest, self)._get_flags()
        f['osapi_share_extension'] = FLAGS.osapi_share_extension[:]
        f['osapi_share_extension'].append(
            'manila.tests.api.extensions.foxinsocks.Foxinsocks')
        return f

    def test_get_foxnsocks(self):
        """Simple check that fox-n-socks works."""
        response = self.api.api_request('/foxnsocks')
        foxnsocks = response.read()
        LOG.debug("foxnsocks: %s" % foxnsocks)
        self.assertEqual('Try to say this Mr. Knox, sir...', foxnsocks)
