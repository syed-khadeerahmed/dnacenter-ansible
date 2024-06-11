#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
 
from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = ("Ajith Andrew J, Syed Khadeer Ahmed")
 
DOCUMENTATION = ""
EXAMPLES = ""
RETURN = ""
 
import re
from dnacentersdk import api
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_int,
    validate_str
)
from ansible.module_utils.basic import AnsibleModule
 
class UserWorkflowManager(DnacBase):
    """Class containing member attributes for DNAC Access Point Automation module"""
 
    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged"]
        self.payload = module.params
        self.keymap = {}
        self.baseurl = "https://" + module.params["dnac_host"]+ ":" + module.params["dnac_port"]
        self.log('Login DNAC using by user: ' + module.params["dnac_username"], "INFO")
        try:
            self.dnacsdk = api.DNACenterAPI(base_url=self.baseurl,
                                    username = module.params["dnac_username"],
                                    password = module.params["dnac_password"],
                                    verify = False)
 
        except Exception as e:
            self.log("Unable to Login DNAC "+ str(e) , "ERROR")
 
def main():
    """ main entry point for module execution
    """
    # Basic Ansible type check or assign default.
    user_details = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin'},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    'config_verify': {'type': 'bool', "default": False},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'dict'},
                    'validate_response_schema': {'type': 'bool', 'default': True}
                }
    module = AnsibleModule(
        argument_spec=user_details,
        supports_check_mode=True
    )
 
    ccc_network = UserWorkflowManager(module)
 
    # Check the Input file should not be empty config param
    if len(module.params.get('config').get("update_users")) < 1:
        module.fail_json(msg='User Should not be Empty, You may forget to pass input.yml',
                         **ccc_network.result)
 
    module.exit_json(**ccc_network.result)
 
if __name__ == '__main__':
    main()
