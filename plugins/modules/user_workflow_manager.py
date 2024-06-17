#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
__author__ = ("Ajith Andrew J, Syed khadeer Ahmed")

DOCUMENTATION = r"""
---
module: user
short_description: Resource module for managing Users in Cisco DNA Center
description:
  - Manages operations to create, update, and delete users in the Cisco DNA Center system.
  - Allows adding a new user.
  - Supports updating an existing user.
  - Enables deleting a user.
version_added: '6.7.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Syed Khadeer Ahmed (@syed-khadeerahmed)
  - Ajith Andrew J (@ajithandrewj)

options:
  create_user:
    email:
      description: The email address of the user.
      type: str
    firstName:
      description: The first name of the user.
      type: str
    lastName:
      description: The last name of the user.
      type: str
    password:
      description: The password for the user's account.
      type: str
    username:
      description: The username for the user's account.
      type: str
    roleList:
      description: A list of role IDs assigned to the user.
      elements: str
      type: list

  update_user:
    email:
      description: The email address of the user. This must be set if the original value is not empty.
      type: str
    firstName:
      description: The first name of the user. This must be set if the original value is not empty.
      type: str
    lastName:
      description: The last name of the user. This must be set if the original value is not empty.
      type: str
    username:
      description: The username for the user's account.
      type: str
    roleList:
      description: A list of role IDs assigned to the user.
      elements: str
      type: list

  delete_user:
    username:
      description: The username of the user to be deleted.
      type: str
      required: true

requirements:
  - dnacentersdk >= 2.7.1
  - python >= 3.10

see also:
  - name: Cisco DNA Center documentation for User and Roles AddUserAPI
    description: Complete reference of the AddUserAPI API.
    link: https://developer.cisco.com/docs/dna-center/#!add-user-api
  - name: Cisco DNA Center documentation for User and Roles UpdateUserAPI
    description: Complete reference of the UpdateUserAPI API.
    link: https://developer.cisco.com/docs/dna-center/#!update-user-api
  - name: Cisco DNA Center documentation for User and Roles DeleteUserAPI
    description: Complete reference of the DeleteUserAPI API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-user-api

notes:
  - SDK Methods used:
    - user_and_roles.UserandRoles.get_user_ap_i
    - user_and_roles.UserandRoles.add_user_ap_i
    - user_and_roles.UserandRoles.update_user_ap_i
    - user_and_roles.UserandRoles.delete_user_ap_i
    - user_and_roles.UserandRoles.get_roles_ap_i
  - Paths used:
    - get /dna/system/api/v1/user
    - post /dna/system/api/v1/user
    - put /dna/system/api/v1/user
    - delete /dna/system/api/v1/user/{userId}
    - get /dna/system/api/v1/roles
"""

EXAMPLES = r"""
---
  - name: Create User
    cisco.dnac.user_workflow_manager:
      dnac_host: "{{ dnac_host }}"
      dnac_username: "{{ dnac_username }}"
      dnac_password: "{{ dnac_password }}"
      dnac_verify: "{{ dnac_verify }}"
      dnac_port: "{{ dnac_port }}"
      dnac_version: "{{ dnac_version }}"
      dnac_debug: "{{ dnac_debug }}"
      state: merged
      config:
        email: "syedkhadeer@example.com"
        firstName: "Syed Khadeer"
        lastName: "Ahmed"
        password: "password123"
        roleList:
          - "Network Administrator"
        username: "syed"

  - name: Update User
    cisco.dnac.user_workflow_manager:
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
        firstName: "Ajith"
        lastName: "Andrew"
        roleList:
          - "System Administrator"
        username: "ajith"

  - name: Delete User
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

RETURN = r"""
# Case 1: User operation successful (create/update/delete)
response_1:
  description: A dictionary with details of the API execution from Cisco DNA Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
        "bapiExecutionId": "string",
        "bapiKey": "string",
        "bapiName": "string",
        "endTime": "string",
        "endTimeEpoch": 0,
        "runtimeInstanceId": "string",
        "userId": "string",  # User ID from Cisco DNA Center
        "startTime": "string",
        "startTimeEpoch": 0,
        "status": "string",  # Status of the operation
        "timeDuration": 0
      },
      "msg": "User operation successful."
    }

# Case 2: User exists and no action needed (for update)
response_2:
  description: A dictionary with existing user details indicating no update needed.
  returned: always
  type: dict
  sample:
    {
      "response": {
        "user": {
          "email": "user@example.com",
          "firstName": "John",
          "lastName": "Doe",
          "username": "johndoe",
          "roleList": ["Network Administrator"]
          # Additional user details as needed
        },
        "userId": "string",  # User ID from Cisco DNA Center
        "type": "string"
      },
      "msg": "User already exists and no update needed."
    }

# Case 3: Error during user operation (create/update/delete)
response_3:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
        "bapiError": "string",  # Specific error message
        "bapiExecutionId": "string",
        "bapiKey": "string",
        "bapiName": "string",
        "endTime": "string",
        "endTimeEpoch": 0,
        "runtimeInstanceId": "string",
        "startTime": "string",
        "startTimeEpoch": 0,
        "status": "string",
        "timeDuration": 0
      },
      "msg": "Error during creating or updating or deliting the user."
    }

# Case 4: User not found (during delete operation)
response_4:
  description: A dictionary indicating user not found during delete operation.
  returned: always
  type: dict
  sample:
    {
      "response": [],
      "msg": "User not found."
    }

# Case 5: Role not found (during get operation)
response_5:
  description: A dictionary indicating role not found during get operation.
  returned: always
  type: dict
  sample:
    {
      "response": [],
      "msg": "Role not found."
    }
"""

import re, time
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_int,
    validate_str,
    validate_list
)
from ansible.module_utils.basic import AnsibleModule

class User(DnacBase):
    """Class containing member attributes for user workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged", "deleted"]
        self.payload = module.params
        self.keymap = {}

    # Below function used to validate input over the ansible validation
    def validate_input_yml(self):
        """
        Validate the fields provided in the yml files.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types based on input.
        Parameters:
          - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
          The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input_yml' on it.
            If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
            will contain the validated configuration. If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
          If the validation succeeds, this will allow to go next step, unless this will stop execution.
          based on the fields.
        """
        self.log('Validating the Playbook Yaml File..', "INFO")
        try:
            errormsg = []
            userlist = self.payload.get("config")
            userlist = self.camel_to_snake_case(userlist)
            userlist = self.update_site_type_key(userlist)
            user_details = dict(first_name = dict(required=False, type='str'),
                        last_name = dict(required=False, type='str'),
                        email = dict(required=False, type='str'),
                        password = dict(required=False, type='str'),
                        username = dict(required=False, type='str'),
                        role_list = dict(required=False, type='list', elements='str'),
                        )
            valid_param, invalid_param = validate_list_of_dicts(userlist, user_details)
            eachuser = valid_param[0]
            if len(invalid_param) > 0:
                errormsg.append("Invalid param found in playbook: '{0}' "\
                                .format(", ".join(invalid_param)))
            self.log(str(eachuser) + str(valid_param), "INFO")

            if eachuser.get("first_name"):
                param_spec = dict(type = "str", length_max = 255)
                validate_str(eachuser["first_name"], param_spec, "first_name",
                                errormsg)

            if eachuser.get("last_name"):
                param_spec = dict(type = "str", length_max = 255)
                validate_str(eachuser["last_name"], param_spec, "last_name",
                                errormsg)

            if eachuser.get("email"):
                param_spec = dict(type = "str", length_max = 255)
                validate_str(eachuser["password"], param_spec, "email",
                                errormsg)

            if eachuser.get("password"):
                param_spec = dict(type = "str", length_max = 255)
                validate_str(eachuser["password"], param_spec, "password",
                                errormsg)

            if eachuser.get("username"):
                param_spec = dict(type = "str", length_max = 255)
                validate_str(eachuser["username"], param_spec, "username",
                                errormsg)

            if eachuser.get("role_list"):
                param_spec = dict(type = "list", elements="str")
                validate_list(eachuser["role_list"], param_spec, "role_list",
                                errormsg)

            if len(errormsg) > 0:
                self.log("Invalid parameters in playbook file: '{0}' ".format(str("\n".join(errormsg))), "ERROR")
                self.module.fail_json(msg=str("\n".join(errormsg)))
            else:
                self.validated_config = valid_param
                self.msg = "Successfully validated playbook config params: {0}".format(str(valid_param))
                self.log(self.msg, "INFO")
                self.status = "success"
                return self

        except Exception as e:
            self.log("Invalid Param provided in playbook Yml File. {0}".format(str(e)), "ERROR")
            self.msg = "Invalid parameters in playbook: {0}".format(str("\n".join(errormsg)))
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
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                }

    module = AnsibleModule(
        argument_spec=user_details,
        supports_check_mode=True
    )

    ccc_user = User(module)
    state = ccc_user.params.get("state")

    if state not in ccc_user.supported_states:
        ccc_user.status = "invalid"
        ccc_user.msg = "State {0} is invalid".format(state)
        ccc_user.check_return_status()

    ccc_user.validate_input_yml().check_return_status()
    config_verify = ccc_user.params.get("config_verify")

    # for config in ccc_user.validated_config:
    #     ccc_user.reset_values()
    #     ccc_user.get_want(config).check_return_status()
    #     ccc_user.get_have(config).check_return_status()
    #     ccc_user.get_diff_state_apply[state](config).check_return_status()
    #     if config_verify:
    #         ccc_user.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_user.result)

if __name__ == '__main__':
    main()
