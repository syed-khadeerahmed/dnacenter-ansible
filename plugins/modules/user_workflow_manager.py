#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Ajith Andrew J, Syed khadeer Ahmed")

DOCUMENTATION = r"""
---
module: site_workflow_manager
short_description: Resource module for Site operations
description:
- Manage operation create, update and delete of the resource Sites.
- Creates site with area/building/floor with specified hierarchy.
- Updates site with area/building/floor with specified hierarchy.
- Deletes site with area/building/floor with specified hierarchy.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Ajith Andrew J 
"""

EXAMPLES = r"""
  - name: Create a new user
    cisco.dnac.user_workflow_manager:
      dnac_host: "{{dnac_host}}"
      dnac_username: "{{dnac_username}}"
      dnac_password: "{{dnac_password}}"
      dnac_verify: "{{dnac_verify}}"
      dnac_port: "{{dnac_port}}"
      dnac_version: "{{dnac_version}}"
      dnac_debug: "{{dnac_debug}}"
      dnac_log: True
      dnac_log_level: DEBUG
      config_verify: True
      state: merged
      config:
        firstName: "ajith"
        lastName: "andrew"
        email: "ajith.andrew@ltts.com"
        password: "ajith@123"
        username: "ajithandrewj"
        roleList:
          - "super-admin"
"""

RETURN = r"""
#Case_1: User is successfully created/updated/deleted
"""

from ansible.module_utils.basic import AnsibleModule

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
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                }
    module = AnsibleModule(
        argument_spec=user_details,
        supports_check_mode=True
    )
 
    module.exit_json()
 
if __name__ == '__main__':
    main()
