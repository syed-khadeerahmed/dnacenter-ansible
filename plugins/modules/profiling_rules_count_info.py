#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: profiling_rules_count_info
short_description: Information module for Profiling Rules Count
description:
- Get all Profiling Rules Count.
- This API fetches the count of profiling rules based on the filter values provided in the query parameters.
  The filter parameters are same as that of 'GET /profiling-rules' API, excluding the pagination and sort parameters.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  ruleType:
    description:
    - RuleType query parameter. Use comma-separated list of rule types to filter the data. Defaults to 'Custom Rule'.
    type: str
  includeDeleted:
    description:
    - IncludeDeleted query parameter. Flag to indicate whether deleted rules should be part of the records fetched.
    type: bool
requirements:
- dnacentersdk >= 2.4.0
- python >= 3.5
notes:
  - SDK Method used are
    policy.Policy.get_count_of_profiling_rules
  - Paths used are get /dna/intent/api/v1/endpoint-analytics/profiling-rules/count
"""

EXAMPLES = r"""
- name: Get all Profiling Rules Count
  cisco.dnac.profiling_rules_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    ruleType: string
    includeDeleted: True
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "count": 0
    }
"""
