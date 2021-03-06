# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
Mock unit tests for the NetApp driver protocols base class module.
"""

from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila import test


class NetAppNASHelperBaseTestCase(test.TestCase):

    def test_set_client(self):
        # The base class is abstract, so we'll use a subclass to test
        # base class functionality.
        helper = cifs_cmode.NetAppCmodeCIFSHelper()
        self.assertIsNone(helper._client)

        helper.set_client('fake_client')
        self.assertEqual('fake_client', helper._client)
