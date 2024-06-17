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
  sample: >
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
  sample: >
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
  sample: >
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
)

class User(DnacBase):
    """Class containing member attributes for user workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.created_user_list, self.updated_user_list, self.update_not_neeeded_user = [], [], []
        self.deleted_user_list, self.user_absent_list = [], []

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

    module.exit_json(**ccc_user.result)

if __name__ == '__main__':
    main()
