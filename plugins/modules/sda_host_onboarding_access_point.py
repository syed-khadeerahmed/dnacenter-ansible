#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, first last <email>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    "metadata_version": "0.0.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: sda_host_onboarding_access_point
short_description: Manage SdaHostOnboardingAccessPoint objects of Sda
description:
- Delete Port assignment for access point in SDA Fabric.
- Get Port assignment for access point in SDA Fabric.
- Add Port assignment for access point in SDA Fabric.
version_added: '1.0'
author: first last (@GitHubID)
options:
    device_ip:
        description:
        - Device-ip query parameter.
        type: str
    interface_name:
        description:
        - InterfaceName query parameter.
        type: str
    payload:
        description:
        - An object to send in the Request body.
        type: list
        required: True
        elements: dict
        suboptions:
            siteNameHierarchy:
                description:
                - It is the sda host onboarding access point's siteNameHierarchy.
                type: str
            deviceManagementIpAddress:
                description:
                - It is the sda host onboarding access point's deviceManagementIpAddress.
                type: str
            interfaceName:
                description:
                - It is the sda host onboarding access point's interfaceName.
                type: str
            dataIpAddressPoolName:
                description:
                - It is the sda host onboarding access point's dataIpAddressPoolName.
                type: str
            voiceIpAddressPoolName:
                description:
                - It is the sda host onboarding access point's voiceIpAddressPoolName.
                type: str
            authenticateTemplateName:
                description:
                - It is the sda host onboarding access point's authenticateTemplateName.
                type: str


requirements:
- dnacentersdk
seealso:
# Reference by module name
- module: cisco.dnac.plugins.module_utils.definitions.sda_host_onboarding_access_point
# Reference by Internet resource
- name: SdaHostOnboardingAccessPoint reference
  description: Complete reference of the SdaHostOnboardingAccessPoint object model.
  link: https://developer.cisco.com/docs/dna-center/api/1-3-3-x
# Reference by Internet resource
- name: SdaHostOnboardingAccessPoint reference
  description: SDK reference.
  link: https://dnacentersdk.readthedocs.io/en/latest/api/api.html#v2-1-1-summary
"""

EXAMPLES = r"""
"""

RETURN = r"""
data_0:
    description: Delete Port assignment for access point in SDA Fabric.
    returned: success,changed,always
    type: dict
    contains:
        status:
            description: Status, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<status>'
        description:
            description: Description, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<description>'
        executionStatusUrl:
            description: Execution Status Url, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<executionstatusurl>'

data_1:
    description: Get Port assignment for access point in SDA Fabric.
    returned: success,changed,always
    type: dict
    contains:
        status:
            description: Status, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<status>'
        description:
            description: Description, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<description>'
        siteNameHierarchy:
            description: Site Name Hierarchy, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<sitenamehierarchy>'
        deviceManagementIpAddress:
            description: Device Management Ip Address, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<devicemanagementipaddress>'
        interfaceName:
            description: Interface Name, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<interfacename>'
        dataIpAddressPoolName:
            description: Data Ip Address Pool Name, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<dataipaddresspoolname>'
        voiceIpAddressPoolName:
            description: Voice Ip Address Pool Name, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<voiceipaddresspoolname>'
        scalableGroupName:
            description: Scalable Group Name, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<scalablegroupname>'
        authenticateTemplateName:
            description: Authenticate Template Name, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<authenticatetemplatename>'

data_2:
    description: Add Port assignment for access point in SDA Fabric.
    returned: success,changed,always
    type: dict
    contains:
        status:
            description: Status, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<status>'
        description:
            description: Description, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<description>'
        executionStatusUrl:
            description: Execution Status Url, property of the response body.
            returned: success,changed,always
            type: str
            sample: '<executionstatusurl>'

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    ModuleDefinition,
    DNACModule,
    dnac_argument_spec,
)
from ansible_collections.cisco.dnac.plugins.module_utils.definitions.sda_host_onboarding_access_point import (
    module_definition,
)


def main():

    moddef = ModuleDefinition(module_definition)

    argument_spec = dnac_argument_spec()
    argument_spec.update(moddef.get_argument_spec_dict())

    required_if = moddef.get_required_if_list()

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=False, required_if=required_if
    )

    dnac = DNACModule(module, moddef)

    state = module.params.get("state")

    if state == "query":
        dnac.exec("get")

    elif state == "delete":
        dnac.exec("delete")

    elif state == "create":
        dnac.disable_validation()
        dnac.exec("post")

    dnac.exit_json()


if __name__ == "__main__":
    main()
