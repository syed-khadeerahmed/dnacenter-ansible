#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
 
from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = ("Ajith Andrew J, Syed Khadeer Ahmed")
 
DOCUMENTATION = r"""
---
module: user
short_description: Resource module for User
description:
- Manage operations create and update of the resource User.
- Add a new user for Cisco DNA Center system.
- Update a user for Cisco DNA Center system.
- Delete a user for cisco DNA Center system
version_added: '6.7.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Syed Khadeer Ahmed (@syed-khadeerahmed)
        Ajith Andrew J(@ajithandrewj)
 
Create user options:
  email:
    description: Email.
    type: str
  firstName:
    description: First Name.
    type: str
  lastName:
    description: Last Name.
    type: str
  password:
    description: Password.
    type: str
  username:
    description: Username.
    type: str
  roleList:
    description: Role id list.
    elements: str
    type: list
 
Update user Options
  email:
    description: Email. Email should be set if the original value is not empty
    type: str
  firstName:
    description: First Name. FirstName should be set if the original value is not empty
    type: str
  lastName:
    description: Last Name. LastName should be set if the original value is not empty
    type: str
  username:
    description: Username.
    type: str
  roleList:
    description: Role id list.
    elements: str
    type: list
 
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for User and Roles AddUserAPI
  description: Complete reference of the AddUserAPI API.
  link: https://developer.cisco.com/docs/dna-center/#!add-user-api
- name: Cisco DNA Center documentation for User and Roles UpdateUserAPI
  description: Complete reference of the UpdateUserAPI API.
  link: https://developer.cisco.com/docs/dna-center/#!update-user-api
- name: Cisco DNA Center documentation for User and Roles UpdateUserAPI
  description: Complete reference of the UpdateUserAPI API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-user-api
 
notes:
  - SDK Method used are
    user_and_roles.UserandRoles.add_user_ap_i,
    user_and_roles.UserandRoles.update_user_ap_i,
    user_and_roles.UserandRoles.delete_user_ap_i,
 
  - Paths used are
    post /dna/system/api/v1/user,
    put /dna/system/api/v1/user,
    delete /dna/system/api/v1/user/{userId}
"""
EXAMPLES = r"""
---
-name: Create User
  cisco.dnac.user_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: Merged
    config:
      email: "syedkhadeer@example.com"
      firstName: "Syed Khadeer"
      lastName: "Ahmed"
      password: "password123"
      roleList:
        - "Network Administrator"
      username: "syed"
 
-name: Update User
  cisco.dnac. user_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: present
    config:
      email: "ajithandrew@example.com"
      firstName: "Ajith "
      lastName: "Andrew"
      roleList:
        - "system Administrator"
        username: "ajith"
 
-name: Delete  User
  cisco.dnac.user_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    state: absent
    config:
      username: "joel"
"""
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
    """Class containing member attributes for DNAC User Automation module"""
 
    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged"]
        self.payload = module.params
        self.keymap = {}
        self.baseurl = "https://" + module.params["dnac_host"] + ":" + module.params["dnac_port"]
        self.log('Login DNAC using by user: ' + module.params["dnac_username"], "INFO")
        try:
            self.dnacsdk = api.DNACenterAPI(base_url=self.baseurl,
                                            username=module.params["dnac_username"],
                                            password=module.params["dnac_password"],
                                            verify=False)
        except Exception as e:
            self.log("Unable to Login DNAC " + str(e), "ERROR")
 
    # Below function used to validate input over the ansible validation
    def validate_input_yml(self, inputdata):
        self.log('Validating the Yaml File..', "INFO")
        try:
            if not isinstance(inputdata, dict):
                raise ValueError("Expected inputdata to be a dictionary")
 
            errormsg = []
            userlist = inputdata.get("config", {}).get("update_users", [])
            if not userlist:
                errormsg.append("No users provided in the 'update_users' list.")
            for eachuser in userlist:
                if not isinstance(eachuser, dict):
                    errormsg.append("Each user entry must be a dictionary.")
                    continue
 
                temp_spec = dict(eachuser=dict(type='dict'))
                eachuser = self.camel_to_snake_case(eachuser)
 
                user_info = dict(firstName=dict(type='str'),
                                 lastName=dict(type='str'),
                                 email=dict(type='str'),
                                 username=dict(type='str'),
                                 userId=dict(type='str'),
                                 roleList=dict(type='list', elements='str'),
                                 )
 
                valid_param, invalid_param = validate_list_of_dicts(eachuser, user_info)
                if invalid_param:
                    errormsg.append(f"Invalid param found '{', '.join(invalid_param)}' in input")
 
                if eachuser.get("firstName"):
                    param_spec = dict(type="str", length_max=32)
                    validate_str(eachuser["firstName"], param_spec, "firstName", errormsg)
 
                if eachuser.get("lastName"):
                    param_spec = dict(type="str", length_max=32)
                    validate_str(eachuser["lastName"], param_spec, "lastName", errormsg)
 
                if eachuser.get("email"):
                    param_spec = dict(type="str", length_max=255)
                    validate_str(eachuser["email"], param_spec, "email", errormsg)
 
                if eachuser.get("username"):
                    param_spec = dict(type="str", length_max=255)
                    validate_str(eachuser["username"], param_spec, "username", errormsg)
 
                if eachuser.get("userId"):
                    param_spec = dict(type="str", length_max=255)
                    validate_str(eachuser["userId"], param_spec, "userId", errormsg)
 
                if eachuser.get("roleList"):
                    if not isinstance(eachuser["roleList"], list):
                        errormsg.append("roleList must be a list.")
                    else:
                        for role in eachuser["roleList"]:
                            param_spec = dict(type="str", length_max=255)
                            validate_str(role, param_spec, "roleList item", errormsg)
 
            if errormsg:
                self.log("Invalid Input in input file: '{0}' ".format(str("\n".join(errormsg))), "ERROR")
                self.module.fail_json(msg=str("\n".join(errormsg)))
 
        except Exception as e:
            self.log("Invalid Param provided in input Yml File. {0}".format(str(e)), "ERROR")
            self.msg = "Invalid parameters in playbook: {0}".format(str(e))
            self.status = "failed"
            return self
 
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
    if not module.params.get('config') or not module.params['config'].get("update_users"):
        module.fail_json(msg='User Should not be Empty, You may forget to pass input.yml',
                         **ccc_network.result)
 
    ccc_network.validate_input_yml(module.params)
 
    module.exit_json(**ccc_network.result)
 
if __name__ == '__main__':
    main()
