# Copyright (c) 2020 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Make coding more python3-ish

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from unittest.mock import patch
from ansible_collections.cisco.dnac.plugins.modules import wireless_design_workflow_manager
from .dnac_module import TestDnacModule, set_module_args, loadPlaybookData


class TestWirelessDesign(TestDnacModule):
    module = wireless_design_workflow_manager
    test_data = loadPlaybookData("wireless_design_workflow_manager_intent")
    # playbooks for wireless_design_workflow_manager enhancements (feature_template)
    playbook_aaa_radius_attribute = test_data.get("playbook_aaa_radius_attribute")
    playbook_aaa_radius_attribute_update = test_data.get("playbook_aaa_radius_attribute_update")
    playbook_aaa_radius_attribute_delete = test_data.get("playbook_aaa_radius_attribute_delete")
    
    playbook_advanced_ssid_create = test_data.get("playbook_advanced_ssid_create")
    playbook_advanced_ssid_update = test_data.get("playbook_advanced_ssid_update")
    playbook_advanced_ssid_delete = test_data.get("playbook_advanced_ssid_delete")
    
    playbook_clean_air_create = test_data.get("playbook_clean_air_create")
    playbook_clean_air_update = test_data.get("playbook_clean_air_update")
    playbook_clean_air_delete = test_data.get("playbook_clean_air_delete")

    playbook_dot11ax_add = test_data.get("playbook_dot11ax_add")
    playbook_dot11ax_update = test_data.get("playbook_dot11ax_update")
    

    def setUp(self):
        super(TestWirelessDesign, self).setUp()

        self.mock_dnac_init = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK.__init__"
        )
        self.run_dnac_init = self.mock_dnac_init.start()
        self.run_dnac_init.side_effect = [None]
        self.mock_dnac_exec = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK._exec"
        )
        self.run_dnac_exec = self.mock_dnac_exec.start()
        self.load_fixtures()

        print(f"Mock for DNACSDK._exec: {self.run_dnac_exec}")

    def tearDown(self):
        super(TestWirelessDesign, self).tearDown()
        self.mock_dnac_init.stop()
        self.mock_dnac_exec.stop()

    def load_fixtures(self, response=None, device=""):
        print("Inside load_fixtures")
        # FIXTURE FOR SUCCESS TESTCASES ############################################################

        if "create_ssid" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("respone_get_sites_success"),
                self.test_data.get("response_get_ssid_by_site_iteration_1_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("respone_get_sites_success"),
                self.test_data.get("response_get_ssids_post_creation_success"),
            ]

        if "update_ssid" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("respone_get_sites_success"),
                self.test_data.get("response_get_ssid_by_site_update_iteration_1_success"),
                self.test_data.get("response_get_sites_2_success"),
                self.test_data.get("response_get_ssid_by_site_empty_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("respone_get_sites_success"),
                self.test_data.get("response_get_ssids_post_update_success"),
                self.test_data.get("response_get_sites_2_success"),
                self.test_data.get("response_get_ssids_post_update_success"),
            ]

        if "delete_ssid" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("respone_get_sites_success"),
                self.test_data.get("response_get_ssid_by_site_delete_iteration_1_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_ssids_post_delete_success"),
            ]

        if "create_interfaces" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_interfaces_1_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_interfaces_post_create_success"),
            ]

        if "update_interfaces" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_interfaces_2_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_interfaces_2_post_update_success"),
            ]

        if "delete_interfaces" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_interfaces_3_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_interfaces_3_post_delete_success"),
            ]

        if "add_power_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_power_profiles_1_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_power_profiles_1_post_create_success"),
            ]

        if "update_power_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_power_profiles_2_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_power_profiles_2_post_update_success"),
            ]

        if "delete_power_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_power_profiles_3_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_power_profiles_3_post_delete_success"),
            ]

        if "create_ap_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_ap_profiles_1_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_ap_profiles_1_post_create_success"),
            ]

        if "update_ap_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_ap_profiles_2_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_ap_profiles_2_post_update_success"),
            ]

        if "delete_ap_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_ap_profiles_3_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_ap_profiles_3_post_delete_success"),
            ]

        if "create_rf_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_rf_profiles_1_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_rf_profiles_1_post_create_success"),
            ]

        if "update_rf_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_rf_profiles_2_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_rf_profiles_2_post_update_success"),
            ]

        if "delete_rf_profiles" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_rf_profiles_3_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_rf_profiles_3_post_delete_success"),
            ]

        if "create_anchor_groups" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_anchor_groups_1_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_anchor_groups_1_post_create_success"),
            ]

        if "update_anchor_groups" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_anchor_groups_2_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_anchor_groups_2_post_update_success"),
            ]

        if "delete_anchor_groups" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("response_get_anchor_groups_3_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_task_id_success"),
                self.test_data.get("response_get_task_status_by_id_success"),
                self.test_data.get("response_get_anchor_groups_3_post_delete_success"),
            ]

        if "playbook_aaa_radius_attribute" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("Get_AAA_RADIUS_ATTRIBUTES_CONFIGURATION"),
                self.test_data.get("Create_AAA_Radius_Attribute"),
                self.test_data.get("task_019a0599-07b7-7f20-a2e2-cffc4eccb372"),
            ]

        if "playbook_aaa_radius_attribute_update" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("Get_AAA_RADIUS_ATTRIBUTES_CONFIGURATION_update"),
                self.test_data.get("Update_AAA_Radius_Attribute"),
                self.test_data.get("Update_AAA_Radius_Attribute_"),
                self.test_data.get("task_019a05af-03ca-78c2-afde-264247f40bad"),
            ]

        if "playbook_aaa_radius_attribute_delete" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("Get_AAA_RADIUS_ATTRIBUTES_CONFIGURATION_delete"),
                self.test_data.get("delete_AAA_RADIUS_ATTRIBUTES_CONFIGURATION"),
                self.test_data.get("task_019a05c6-1eee-7459-9ac8-d09c60c33845"),
            ]

        if "playbook_advanced_ssid_create" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("ADVANCED_SSID_CONFIGURATION"),
                self.test_data.get("create_ADVANCED_SSID_CONFIGURATION"),
                self.test_data.get("task_019a05e4-e2cd-7fe9-895a-3a86eaae5514"),
            ]

        if "playbook_advanced_ssid_update" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("ADVANCED_SSID_CONFIGURATION_update"),
                self.test_data.get("ADVANCED_SSID_CONFIGURATION_update_"),
                self.test_data.get("update_ADVANCED_SSID_CONFIGURATION"),
                self.test_data.get("task_019a05ff-25bb-7464-aa52-ae50f9ea6e11"),
            ]
        if "playbook_advanced_ssid_delete" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("ADVANCED_SSID_CONFIGURATION_delete"),
                self.test_data.get("delete_ADVANCED_SSID_CONFIGURATION"),
                self.test_data.get("task_019a0616-094f-7d81-9d8c-2d371bf1daed"),
            ]
            
        if "playbook_clean_air_create" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("get_CLEANAIR_CONFIGURATION"),
                self.test_data.get("CLEANAIR_CONFIGURATION_create"),
                self.test_data.get("task_019a0b14-1380-7afc-a82e-a27c917eff36"),
            ]

        if "playbook_clean_air_update" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("CLEANAIR_CONFIGURATION_get_update"),
                self.test_data.get("CLEANAIR_CONFIGURATION_update_get"),
                self.test_data.get("CLEANAIR_CONFIGURATION_update"),
                self.test_data.get("task_019a0b1f-1e68-7d22-a6e5-4edb47eeb423"),
            ]

        if "playbook_clean_air_delete" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("CLEANAIR_CONFIGURATION_get_delete"),
                self.test_data.get("CLEANAIR_CONFIGURATION_delete_get"),
                self.test_data.get("task_019a0b25-4304-70f0-a684-889e06e10841"),
            ]

        if "playbook_dot11ax_add" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("DOT11AX_CONFIGURATION_get"),
                self.test_data.get("DOT11AX_CONFIGURATION_create"),
                self.test_data.get("task_019a0b40-98f2-7d60-b662-1fa7b0d18246"),
            ]

        if "playbook_dot11ax_update" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("DOT11AX_CONFIGURATION_get_update"),
                self.test_data.get("DOT11AX_CONFIGURATION_update_get"),
                self.test_data.get("DOT11AX_CONFIGURATION_update"),
                self.test_data.get("task_019a0b4b-4ddd-7717-95dc-d224a3dc0213"),
            ]

    # SUCCESS TESTCASES ########################################################################################

    def test_create_ssid(self):
        print("Test Data: {test_data}".format(test_data=self.test_data.get("playbook_config_create_ssids")))

        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_create_ssids"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Create SSID(s) Task succeeded for the following SSID(s)",
            result.get("msg"),
        )

    def test_update_ssid(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_update_ssids"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Update SSID(s) Task succeeded for the following SSID(s)",
            result.get("msg"),
        )

    def test_delete_ssid(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="deleted",
                config=self.test_data.get("playbook_config_delete_ssids"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Delete SSID(s) Task succeeded for the following SSID(s)",
            result.get("msg"),
        )

    def test_create_interfaces(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_create_interfaces"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Create Interface(s) Task succeeded for the following interface(s)",
            result.get("msg"),
        )

    def test_update_interfaces(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_update_interfaces"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Update Interface(s) Task succeeded for the following interface(s)",
            result.get("msg"),
        )

    def test_delete_interfaces(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="deleted",
                config=self.test_data.get("playbook_config_delete_interfaces"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Delete Interface(s) Task succeeded for the following interface(s)",
            result.get("msg"),
        )

    def test_add_power_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_create_power_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Create Power Profile(s) Task succeeded for the following power profile(s)",
            result.get("msg"),
        )

    def test_update_power_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_update_power_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Update Power Profile(s) Task succeeded for the following power profile(s)",
            result.get("msg"),
        )

    def test_delete_power_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="deleted",
                config=self.test_data.get("playbook_config_delete_power_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Delete Power Profile(s) Task succeeded for the following power profile(s)",
            result.get("msg"),
        )

    def test_create_ap_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_create_ap_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Create Access Point Profile(s) Task succeeded for the following access point profile(s)",
            result.get("msg"),
        )

    def test_update_ap_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_update_ap_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Update Access Point Profile(s) Task succeeded for the following access point profile(s)",
            result.get("msg"),
        )

    def test_delete_ap_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="deleted",
                config=self.test_data.get("playbook_config_delete_ap_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Delete Access Point Profile(s) Task succeeded for the following access point profile(s)",
            result.get("msg"),
        )

    def test_create_rf_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_create_rf_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Create Radio Frequency Profile(s) Task succeeded for the following radio frequency profile(s)",
            result.get("msg"),
        )

    def test_update_rf_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_update_rf_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Update Radio Frequency Profile(s) Task succeeded for the following radio frequency profile(s)",
            result.get("msg"),
        )

    def test_delete_rf_profiles(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="deleted",
                config=self.test_data.get("playbook_config_delete_rf_profiles"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Delete Radio Frequency Profile(s) Task succeeded for the following radio frequency profile(s)",
            result.get("msg"),
        )

    def test_create_anchor_groups(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_create_anchor_groups"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Create Anchor Group(s) Task succeeded for the following anchor group(s)",
            result.get("msg"),
        )

    def test_update_anchor_groups(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="merged",
                config=self.test_data.get("playbook_config_update_anchor_groups"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Update Anchor Group(s) Task succeeded for the following anchor group(s)",
            result.get("msg"),
        )

    def test_delete_anchor_groups(self):
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=False,
                dnac_log_level="DEBUG",
                dnac_version="2.3.7.9",
                config_verify=True,
                dnac_log_append=False,
                state="deleted",
                config=self.test_data.get("playbook_config_delete_anchor_groups"),
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertIn(
            "Delete Anchor Group(s) Task succeeded for the following anchor group(s)",
            result.get("msg"),
        )

    def test_wireless_design_workflow_manager_playbook_aaa_radius_attribute(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_aaa_radius_attribute
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
            {
        "aaa_radius_attributes_add": {
            "sample_design": "Successfully created AAA Radius Attribute."
        }
        }
        )
        
    def test_wireless_design_workflow_manager_playbook_aaa_radius_attribute_update(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_aaa_radius_attribute_update
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
            {
        "aaa_radius_attributes_update": {
            "sample_design": "Successfully updated AAA Radius Attribute."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_aaa_radius_attribute_delete(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="deleted",
                config=self.playbook_aaa_radius_attribute_delete
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
            {
        "aaa_radius_attributes_delete": {
            "sample_design": "Successfully deleted AAA Radius Attribute."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_advanced_ssid_create(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_advanced_ssid_create
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "advanced_ssids_add": {
            "sample_advanced_ssid_design": "Successfully created Advanced SSID."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_advanced_ssid_update(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_advanced_ssid_update
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "advanced_ssids_update": {
            "sample_advanced_ssid_design": "Successfully updated Advanced SSID."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_advanced_ssid_delete(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="deleted",
                config=self.playbook_advanced_ssid_delete
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "advanced_ssids_delete": {
            "sample_advanced_ssid_design": "Successfully deleted Advanced SSID."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_clean_air_create(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_clean_air_create
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "clean_air_add": {
            "sample_cleanair_design_24ghz": "Successfully created CleanAir Profile."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_clean_air_update(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_clean_air_update
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "clean_air_update": {
            "sample_cleanair_design_24ghz": "Successfully updated CleanAir Profile."
        }
    }
        )
    def test_wireless_design_workflow_manager_playbook_clean_air_delete(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="deleted",
                config=self.playbook_clean_air_delete
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "clean_air_delete": {
            "sample_cleanair_design_24ghz": "Successfully deleted CleanAir Profile."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_dot11ax_add(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_dot11ax_add
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "dot11ax_add": {
            "dot11ax_24ghz_design": "Successfully created dot11ax configuration."
        }
    }
        )

    def test_wireless_design_workflow_manager_playbook_dot11ax_update(self):
        set_module_args(
            dict(
                dnac_version='3.1.3.0',
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_log=True,
                state="merged",
                config=self.playbook_dot11ax_update
            )
        )
        result = self.execute_module(changed=True, failed=False)
        self.assertEqual(
            result.get('msg'),
{
        "dot11ax_update": {
            "dot11ax_24ghz_design": "Successfully updated dot11ax configuration."
        }
    }
        )
