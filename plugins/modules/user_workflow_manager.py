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

RETURN = r"""

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
