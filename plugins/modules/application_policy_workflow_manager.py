# !/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_policy_workflow_manager
short_description: Resource module for managing application policies in Cisco Catalyst Center.
description:
  - Manages operations to create, update, and delete application, application set, queuing profile and application policies in Cisco Catalyst Center.
  - API to create application, application set, queuing profile and application policies.
  - API to update application, queuing profile and application policies.
  - API to delete application, application set, queuing profile and application policies.

version_added: "6.17.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Syed Khadeer Ahmed (@syed-khadeerahmed)
  - Madhan Sankaranarayanan (@madhansansel)

options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center after applying the playbook config.
    type: bool
    default: False
  state:
    description: The state of Cisco Catalyst Center after module completion.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: A dictionary containing the details for application queuing profile.
    type: dict
    required: true
    suboptions:
      application_queuing_details:
        description: Manages the details for application queuing profile.
        type: list
        elements: dict
        suboptions:
          queuing_profile_name:
            description:
              - This represent a name for the queuing profile.
              - Required for queuing profile create, update and delete operations.
            type: str
          queuing_profile_description:
            description: The description for queuing profile.
            type: str
          clause:
            description: Inside clause we will get information about the type in which the queuing profile will be created
            type: list
            elements: dict
            suboptions:
              clause_type:
                description: |
                  - The type field determines the method by which traffic prioritization is applied
                  - Either through interface bandwidth allocation or by assigning Differentiated Services Code Point (DSCP) values or both.
                  Permissible values:
                  - "BANDWIDTH": This clause type is used to specify traffic management settings based on bandwidth allocation.
                    It defines how much bandwidth is allocated to different types of traffic within the network"
                  - "DSCP_CUSTOMIZATION" - This clause type deals with Differentiated Services Code Point (DSCP) customization.
                    DSCP is used for Quality of Service (QoS) to categorize and prioritize network traffic
                type: str
              bandwidth_settings:
                description: When the type is "bandwidth", the "tc_bandwidth_settings" will include specific details related to bandwidth allocation
                type: dict
                suboptions:
                  is_common_between_all_interface_speeds:
                    description:
                      - The field indicates that the bandwidth allocation settings defined in the configuration are
                        uniform across all interface speeds or not.
                    type: bool
                  interface_speed_bandwidth_clauses:
                    description:
                      - Define the specific bandwidth allocation for different types of network traffic based on the interface speed.
                      - This clause allows you to specify how bandwidth should be distributed across various traffic categories
                    type: list
                    elements: dict
                    suboptions:
                      interface_speed:
                        description: |
                          - The "interface_speed" refers to the specific data transfer rate (or bandwidth capacity) of a network interface.
                          - It defines how much data the interface can handle within a given period, typically measured in bits per second (bps)
                          - Permissible values:
                            - "ALL": Refers to the total bandwidth applicable across all interface speeds, without specifying a particular speed.
                            - "HUNDRED_GBPS": Represents a bandwidth of 100 gigabits per second (Gbps).
                            - "TEN_GBPS": Represents a bandwidth of 10 gigabits per second (Gbps).
                            - "ONE_GBPS": Represents a bandwidth of 1 gigabit per second (Gbps).
                            - "HUNDRED_MBPS": Represents a bandwidth of 100 megabits per second (Mbps).
                            - "TEN_MBPS": Represents a bandwidth of 10 megabits per second (Mbps).
                            - "ONE_MBPS": Represents a bandwidth of 1 megabit per second (Mbps).
                        type: str
                      bandwidth_percentages:
                        description:
                          - The field specifies the percentage of total available bandwidth that should be allocated to different types of network traffic.
                          - This allocation is used to prioritize specific traffic categories based on their importance or application requirements.
                        type: dict
                        suboptions:
                          transactional_data:
                            description: Refers to a category of network traffic that involves data transactions between systems.
                            type: str
                          best_effort:
                            description:
                              - Refers to a type of network traffic that does not require specific guarantees for quality or priority.
                              - It is typically used for non-critical or general-purpose data transmission
                            type: str
                          voip_telephony:
                            description:
                              - Refers to network traffic for the voice and video calls transmitted over the internet rather
                                than traditional telephone lines.
                            type: str
                          multimedia_streaming:
                            description: Refers to network traffic for the transmission of audio and video content over the internet in real time
                            type: str
                          real_time_interactive:
                            description: Refers to network traffic generated by applications that require low latency and immediate responsiveness.
                            type: str
                          multimedia_conferencing:
                            description: Refers to network traffic that involve both audio and video communication.
                            type: str
                          signaling:
                            description: Refers to network traffic that control messages and protocols used to manage communication sessions in a network.
                            type: str
                          scavenger:
                            description:
                              - Refers to low-priority network traffic that can be delayed or dropped in times of congestion
                                without significant impact on application performance.
                            type: str
                          ops_admin_mgmt:
                            description: Refers to network traffic associated with operations and administration management.
                            type: str
                          broadcast_video:
                            description:
                              - Refers to video content that is broadcasted or streamed to a large audience,
                                typically in a one-to-many distribution model
                            type: str
                          network_control:
                            description: Refers to traffic related to the management and operation of the network itself
                            type: str
                          bulk_data:
                            description: Refers to large-volume data transfers that are typically non-time-sensitive and can tolerate delays or interruptions
                            type: str
              dscp_settings:
                description: When the type is 'DSCP' the 'tc_dscp_settings' will include specific details related to dscp allocation
                type: list
                elements: dict
                suboptions:
                  transactional_data:
                    description: Refers to a category of network traffic that involves data transactions between systems.
                    type: str
                  best_effort:
                    description:
                      - Refers to a type of network traffic that does not require specific guarantees for quality or priority.
                      - It is typically used for non-critical or general-purpose data transmission
                    type: str
                  voip_telephony:
                    description:
                      - Refers to network traffic for the voice and video calls transmitted over the internet or private networks
                        rather than traditional telephone lines.
                    type: str
                  multimedia_streaming:
                    description: Refers to network traffic for the transmission of audio and video content over the internet in real time
                    type: str
                  real_time_interactive:
                    description: Refers to network traffic generated by applications that require low latency and immediate responsiveness.
                    type: str
                  multimedia_conferencing:
                    description: Refers to network traffic that involve both audio and video communication.
                    type: str
                  signaling:
                    description:
                      - Refers to network traffic that control messages and protocols used to establish, manage,
                        and terminate communication sessions in a network.
                    type: str
                  scavenger:
                    description:
                      - Refers to low-priority network traffic that can be delayed or dropped in times of congestion
                        without significant impact on application performance.
                    type: str
                  ops_admin_mgmt:
                    description: Refers to network traffic associated with operations and administration management.
                    type: str
                  broadcast_video:
                    description: Refers to video content that is broadcasted or streamed to a large audience, typically in a one-to-many distribution model
                    type: str
                  network_control:
                    description: Refers to traffic related to the management and operation of the network itself
                    type: str
                  bulk_data:
                    description: Refers to large-volume data transfers that are typically non-time-sensitive and can tolerate delays or interruptions
                    type: str
      application_set_details:
        description:
          - An Application Set is a logical grouping of network applications that share common policies and configuration settings.
          - Application sets allow network administrators to manage and apply policies to multiple applications simultaneously,
            streamlining the process of policy enforcement, monitoring, and optimization.
        type: list
        elements: dict
        suboptions:
          application_set_name:
            description:
              - This field represent a name for the application set.
              - Required for application set create and delete operations.
            type: str
      application_details:
        description:
          - Each application inside an Application Set share a common purpose or function.
          - Group of similar applications inside an application set are classified in a way that allows network administrators to
            apply uniform policies to the entire set.
        type: list
        elements: dict
        suboptions:
          application_name:
            description:
              - This field represent a name for the application.
              - Required for application create, update and delete operations.
            type: str
          network_applications:
            description:
              - Network applications are identified based on their behavior, traffic type, and protocols they use.
              - A Network Application is a service that utilizes network resources to provide functionality, such as
                communication, data transfer, or network management.
            type: list
            elements: dict
            suboptions:
              application_type:
                description: |
                  - The type field in a Network Application refers to the way the application is identified or categorized within the network.
                  - Permissible values:
                  - _servername: Specifies a custom application based on the server name for identifying the application.
                  - _url: Specifies a custom application based on a URL for identifying the application.
                  - _server-ip: Specifies a custom application based on the server IP address for identifying the application.
                type: list
                elements: str
              server_name:
                description:
                  - If the type mentioned is servername then a name for the server has to be mentioned
                type: str
              dscp:
                description:
                  - If the type mentioned is serverip then a value of dscp has to be mentioned
                type: str
              app_protocol:
                description: |
                  If the type mentioned is serverip then the protocol used has to be mentioned
                  Permissible values:
                    - 'TCP': Specifies the Transmission Control Protocol, used for reliable, connection-oriented communication.
                    - 'UDP': Specifies the User Datagram Protocol, used for connectionless, faster communication without guaranteed delivery.
                    - 'TCP/UDP': Indicates both TCP and UDP protocols are used, allowing flexibility in communication.
                    - 'IP': Refers to the Internet Protocol, used for addressing and routing packets in a network.
                type: str
              url:
                description:
                  - If the type mentioned is url then url has to be mentioned
                type: str
              traffic_class:
                description: |
                  - Traffic classes help enforce network policies by determining how to prioritize different types of data, ensuring that critical
                    applications receive the necessary bandwidth while less critical traffic can be deprioritized or handled with lower resources.
                  - Permissible values:
                    - "BROADCAST_VIDEO": Video traffic broadcasted to multiple recipients.
                    - "BULK_DATA": Large data transfers like file uploads or backups.
                    - "MULTIMEDIA_CONFERENCING": Audio and video traffic for conferencing.
                    - "MULTIMEDIA_STREAMING": Streaming video or audio content.
                    - "NETWORK_CONTROL": Traffic for managing and controlling network infrastructure.
                    - "OPS_ADMIN_MGMT": Traffic for network operational and administrative tasks.
                    - "REAL_TIME_INTERACTIVE": Low-latency traffic for real-time interactive applications.
                    - "SIGNALING": Control traffic for setting up and managing sessions (e.g., VoIP).
                    - "TRANSACTIONAL_DATA": Data related to transactions, like financial or retail operations.
                    - "VOIP_TELEPHONY": Voice traffic over IP networks.
                    - "BEST_EFFORT": Non-critical traffic delivered on a best-effort basis.
                    - "SCAVENGER": Low-priority traffic, often background tasks.
                type: str
              category_id:
                description:
                  - If the type mentioned is url then url has to be mentioned
                type: str
          application_set_name:
            description: This represents under which appliction set we are going to create the application
            type: str
      application_policy_details:
        description: Define how an application's traffic is managed and prioritized within a network.
        type: list
        elements: dict
        suboptions:
          application_policy_name:
            description:
              - This field represent a name for the application policy.
            type: str
          delete_policy_details:
            description: |
              - Indicates the current status of the application policy. It helps track whether the policy is active, deleted, or restored.
              - Permissible values:
                - "NONE": The policy is active and in its original, operational state.
                - "DELETED": The policy has been removed and is no longer active.
                - "RESTORED": The policy has been reactivated after being deleted.
            type: str
          priority:
            description: |
              - The priority attribute defines the importance of the application policy
              - Permissible values:
                - 4095: This priority value is used when the producer refers to an application scalable group, indicating the highest priority.
                - 100: This is the default priority value, typically used for non-scalable group applications or when no special priority is needed.
            type: str
          site_name:
            description:
              -  It typically represents the specific site or area within the network where the policy should be enforced.
            type: str
          device_type:
            description:
              -  It typically represents whether the device is wired or wireless
            type: list
            elements: dict
            suboptions:
              device_ip:
                description:
                  - If device type is wireless, specify the device ip.
                  - Indicates is the IP address assigned to the device, used for network communication.
                type: str
              vlan_id:
                description:
                  - If device type is wireless, specify the vlan id.
                  - The VLAN (Virtual Local Area Network) ID associated with the device, used to segment network traffic.
                type: str
          application_queuing_profile_name:
            description:
              - The application_queuing_profile_name determines how the application policy prioritizes network traffic by defining
                rules for traffic management
            type: str
          clause:
            description:
              - The clause is used to define specific rules or conditions under which an application set is added to the application policy
            type: list
            elements: dict
            suboptions:
              clause_type:
                description: |
                  - Specifies the type of clause for the application policy.
                  - Permissible values:
                    - "BUSINESS_RELEVANCE": Defines the importance of the application to business operations, affecting its priority and
                    handling in the network policy.
                    - "APPLICATION_POLICY_KNOBS": Refers to configurable settings that manage the application's network behavior,
                    such as traffic prioritization and resource allocation.
                type: str
              relevance_level:
                description: |
                  - Indicates how relevant the application is to business operations.
                  - Permissible values:
                    - "BUSINESS_RELEVANT": The application is critical for business functions.
                    - "BUSINESS_IRRELEVANT": The application is not essential for business operations.
                    - "DEFAULT": A default setting when no specific relevance is assigned.
                type: str
          #   device_removal_behaviour:
          #     description:
          #     type: str
          #   host_tracking_enabled:
          #     description:
          #     type: boolean
          # producer:
          #   description:
          #   type: list
          #   elements: dict
          #   suboptions:
            #   application_set_name:
            #     description:
            #     type: list
          # consumer:
          #   description:
          #   type: list
          #   elements: dict
          #   suboptions:
            #   application_set_name:
            #     description:
            #     type: list

requirements:
- dnacentersdk >= 2.9.3
- python >= 3.9.19
notes:
- SDK Methods used are
  - application_policy.ApplicationPolicy.get_application_policy
  - application_policy.ApplicationPolicy.application_policy_intent
  - application_policy.ApplicationPolicy.get_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.update_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.create_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.delete_application_policy_queuing_profile
  - application_policy.ApplicationPolicy.get_application_sets
  - application_policy.ApplicationPolicy.create_application_set
  - application_policy.ApplicationPolicy.delete_application_set
  - application_policy.ApplicationPolicy.get_applications
  - application_policy.ApplicationPolicy.create_application
  - application_policy.ApplicationPolicy.update_application
  - application_policy.ApplicationPolicy.delete_application

- Paths used are
  - GET/dna/intent/api/v1/app-policy
  - POST/dna/intent/api/v1/app-policy-intent
  - GET/dna/intent/api/v1/app-policy-queuing-profile
  - POST/dna/intent/api/v1/app-policy-queuing-profile
  - PUT/dna/intent/api/v1/app-policy-queuing-profile
  - DELETE/dna/intent/api/v1/app-policy-queuing-profile/{id}
  - GET/dna/intent/api/v1/application-policy-application-set
  - POST//dna/intent/api/v1/application-policy-application-set
  - DELETE/dna/intent/api/v2/application-policy-application-set/{id}
  - GET/dna/intent/api/v2/applications
  - POST/dna/intent/api/v2/applications
  - PUT/dna/intent/api/v1/applications
  - DELETE/dna/intent/api/v2/applications/{id}
"""

EXAMPLES = r"""
---
#Playbook 1 - application queuing profile - type both ("bandwidth", "dscp")

- name: Application Queueing Profile Creation in Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create a application Queueing Profile in Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          application_queuing_details:
            - queuing_profile_name: "str"
              queuing_policy_description: "str"
              type: ["bandwidth", "dscp"]
              bandwidth_settings:
                is_common_between_all_interface_speeds: true
                interface_speed: "ALL"
                bandwidth_percentages:
                    transactional_data: "5"
                    best_effort: "10"
                    voip_telephony: "15"
                    multimedia_streaming: "10"
                    real_time_interactive: "20"
                    multimedia_conferencing: "10"
                    signaling: "10"
                    scavenger: "5"
                    ops_admin_mgmt: "5"
                    broadcast_video: "2"
                    network_control: "3"
                    bulk_data: "5"
                dscp_settings:
                  multimedia_conferencing: "16"
                  ops_admin_mgmt: "20"
                  transactional_data: "28"
                  voip_telephony: "46"
                  multimedia_streaming: "26"
                  broadcast_video: "40"
                  network_control: "48"
                  best_effort: "0"
                  signaling: "4"
                  bulk_data: "10"
                  scavenger: "2"
                  real_time_interactive: "34"

#Playbook 2 - application queuing profile - type bandwidth

- name: Application Queueing Profile Creation in Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create a application Queueing Profile in Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
        - application_queuing_details:
            - queuing_profile_name: "newprofile1"
              queuing_policy_description: "sample desc"
              type: ["bandwidth"]
              bandwidth_settings:
                is_common_between_all_interface_speeds: true
                interface_speed: "ALL"
                bandwidth_percentages:
                    transactional_data: "5"
                    best_effort: "10"
                    voip_telephony: "15"
                    multimedia_streaming: "10"
                    real_time_interactive: "20"
                    multimedia_conferencing: "10"
                    signaling: "10"
                    scavenger: "5"
                    ops_admin_mgmt: "5"
                    broadcast_video: "2"
                    network_control: "3"
                    bulk_data: "5"

#Playbook 3 - application queuing profile - type dscp

- name: Application Queueing Profile Creation in Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create a application Queueing Profile in Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          application_queuing_details:
            - queuing_profile_name: "str"
              queuing_policy_description: "str"
                type: ["dscp"]
                dscp_settings:
                  multimedia_conferencing: "16"
                  ops_admin_mgmt: "20"
                  transactional_data: "28"
                  voip_telephony: "46"
                  multimedia_streaming: "26"
                  broadcast_video: "40"
                  network_control: "48"
                  best_effort: "0"
                  signaling: "4"
                  bulk_data: "10"
                  scavenger: "2"
                  real_time_interactive: "34"


#Playbook 4 - delete application queuing profile

- name: Delete application queuing profile from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Delete application queuing profile from Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: deleted
        config:
          application_queuing_details:
            - queuing_profile_name: "str"

#Playbook 5 - create application set

- name: Application Set Creation in Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create application set on Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          application_set_details:
            - application_set_name: "str"

#Playbook 6 - delete application set

- name: Application Set deletion from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Delete application set from Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: deleted
        config:
          application_set_details:
            - application_set_name: "str"

#Playbook 7 - create application - type server_name

- name: Create application on Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create application on Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          application_details:
            - application_name: "str"
              network_applications:
                - application_type: [server_name]
                  server_name: "str"
                  traffic_class: "str"
                  category_id: "01440e2c-7cbb-48a9-aa14-df3af28b4582"
              application_set_name: "str"

#Playbook 8 - create application - type server_ip

- name: Create application on Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create application on Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          application_details:
            - application_name: "str"
              network_applications:
                - application_type: [server_ip]
                  dscp: "str"
                  network_identifier
                  app_protocol: "str"
                  traffic_class: "str"
                  category_id: "01440e2c-7cbb-48a9-aa14-df3af28b4582"
              application_set_name: "str"

#Playbook 9 - create application - type url

- name: Create application on Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create application on Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          application_details:
            - application_name: "str"
              network_applications:
                - application_type: [url]
                  url: "str"
                  traffic_class: "str"
                  category_id: "01440e2c-7cbb-48a9-aa14-df3af28b4582"
              application_set_name: "str"

#Playbook 10 - delete application

- name: Delete application from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Delete application from Cisco Catalyst Center
      cisco.dnac.sample_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: true
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: deleted
        config:
          application_details:
            - application_name: "str"

#Playbook 11 - create application policy

- name: Application Policy Creation in Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"

  tasks:
    - name: Create a application Policy in Cisco Catalyst Center
      cisco.dnac.application_policy_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          application_policy_details:
            - application_policy_name: "str"
              delete_policy_status: "str"
              priority: "str"
              site_name: "str"
              device_type: "str"
              device_ip: "str"
              vlan_id: "str"
              application_queuing_profile_name: "str"
              clause:
                - type: "str"
                  relevance_level: "str"
                  device_removal_behaviour: "str"
                  host_tracking_enabled: "boolean"
              producer:
                - application_set_name: "list"
              consumer:
                - application_set_name: "list"

#Playbook 12 - delete application policy

- name: Application Policy Deletion from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"

  tasks:
  - name: Delete application policy from Cisco Catalyst Center
    cisco.dnac.application_policy_workflow_manager:
      dnac_host: "{{ dnac_host }}"
      dnac_username: "{{ dnac_username }}"
      dnac_password: "{{ dnac_password }}"
      dnac_verify: "{{ dnac_verify }}"
      dnac_port: "{{ dnac_port }}"
      dnac_version: "{{ dnac_version }}"
      dnac_debug: "{{ dnac_debug }}"
      dnac_log: True
      dnac_log_level: DEBUG
      config_verify: True
      dnac_api_task_timeout: 1000
      dnac_task_poll_interval: 1
      state: deleted
      config:
        application_policy_details:
          - policy_name: "str"
"""

RETURN = r"""

# Case 1: Successful creation of application queuing profile

creation_of_application_queuing_profile_response_task_tracking:
  description: A dictionary containing task tracking details such as task ID and URL from the Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

creation _of_application_queuing_profile_response_task_execution:
  description: A dictionary with additional details for successful task execution, including progress and data.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str"
      },
      "version": "str"
    }


# Case 2: Successful updation of application queuing profile

updation_of_application_queuing_profile_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

updation_of_application_queuing_profile_response_task_execution:
  description: With task id get details for successfull updation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 3: Successful deletion of application queuing profile

deletion_of_application_queuing_profile_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
deletion_of_application_queuing_profile_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 4: Error during application queuing profile (create/update/delete)

error_during_application_queuing_profile_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_queuing_profile_response_task_execution:
  description: With task id get details for error during application queuing profile (create/update/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 5: Application queuing profile not found (during delete operation)

application_queuing_profile_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_queuing_profile_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }


# Case 6: Successful creation of application set

successful_creation_of_application_set_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_creation_of_application_set_response_task_execution:
  description: With task id get details for successfull creation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 7: Successful deletion of application set

successful_deletion_of_application set_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_deletion_of_application_set_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 8: Error during application set operation (create/delete)

error_during_application_set_operation_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_set_operation_response_task_execution:
  description: With task id get details for error during application set (create/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 9: Application set not found (during delete operation)

application_set_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_set_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 10: Successful creation of application

successful_creation_of_application_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_creation_of_application_response_task_execution:
  description: With task id get details for successfull creation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 11: Successful updation of application

successful updation_of_application_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_updation_of_application_response_task_execution:
  description: With task id get details for successfull updation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 12: Successful deletion of application

deletion_of_application_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

deletion_of_application_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 13: Error during application operation (create/update/delete)

error_during_application_operation_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_operation_response_task_execution:
  description: With task id get details for error during application (create/update/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 14: Application not found (during delete operation)

application_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 15: Successful creation of application policy

successful_creation_of_application_policy_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_creation_of_application_policy_response_task_execution:
  description: With task id get details for successfull creation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

#Case 16: Successful updation of application policy

successful_updation_of_application_policy_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_updation_of_application_policy_response_task_execution:
  description: With task id get details for successfull updation
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 17: Successful deletion of application policy

successful_deletion_of_application_policy_response_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
successful_deletion_of_application_policy_response_task_execution:
  description: With task id get details for successfull deletion
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
      },
      "version": "str"
    }

# Case 18: Error during application policy operation(create/update/delete)

error_during_application_policy_operation_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
error_during_application_policy_operation_response_task_execution:
  description: With task id get details for error during application policy(create/update/delete)
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }

# Case 19: Application policy not found (during delete operation)

application_policy_not_found_response_task_tracking:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }
application_policy_not_found_response_task_execution:
  description: With task id get details for error message
  returned: always
  type: dict
  sample:
    {
      "response": {
          "data": "str",
          "progress": "str",
          "errorCode": "str",
          "failureReason": "str"
      },
      "version": "str"
    }
"""

from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
)
from ansible.module_utils.basic import AnsibleModule
import json

class ApplicationPolicy(DnacBase):
    """Class containing member attributes for application_policy_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
        - self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
        The method returns an instance of the class with updated attributes:
        - self.msg: A message describing the validation result.
        - self.status: The status of the validation (either 'success' or 'failed').
        - self.validated_config: If successful, a validated version of 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
        If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
        will contain the validated configuration. If it fails, 'self.status' will be 'failed',
        'self.msg' will describe the validation issues.
        """
        
        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        # Check if the config is a list, as expected
        if not isinstance(self.config, list):
            self.status = "failed"
            self.msg = "Config should be a list, found: {0}".format(type(self.config))
            self.log(self.msg, "ERROR")
            return self
        
        config_data = self.config[0] if self.config else {}

        # Ensure application_queuing_details is a list
        application_queuing_details = config_data.get('application_queuing_details', [])
        if not isinstance(application_queuing_details, list):
            self.status = "failed"
            self.msg = "'application_queuing_details' should be a list, found: {0}".format(type(application_queuing_details))
            self.log(self.msg, "ERROR")
            return self

        application_set_details = config_data.get('application_set_details', [])
        if not isinstance(application_set_details, list):
            self.status = "failed"
            self.msg = "'application_set_details' should be a list, found: {0}".format(type(application_set_details))
            self.log(self.msg, "ERROR")
            return self
  
        application_details = config_data.get('application_details', [])
        if not isinstance(application_details, list):
            self.status = "failed"
            self.msg = "'application_details' should be a list, found: {0}".format(type(application_details))
            self.log(self.msg, "ERROR")
            return self

        # application_policy_details = config_data.get('application_policy_details', [])
        # self.log(application_policy_details)
        # if not isinstance(application_policy_details, dict):
        #     self.status = "failed"
        #     self.msg = "'application_policy_details' should be a dict, found: {0}".format(type(application_policy_details))
        #     self.log(self.msg, "ERROR")
        #     return self

        # Validate each item in the application_queuing_details list
        for item in application_queuing_details:
            if not isinstance(item, dict):
                self.status = "failed"
                self.msg = "Each item in 'application_queuing_details' should be a dictionary, found: {0}".format(type(item))
                self.log(self.msg, "ERROR")
                return self

        self.validated_config = self.config
        self.msg = "Successfully validated playbook config params"
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def get_want(self, config):
        """
        Retrieve and store import, tagging, distribution, and activation details from playbook configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.
        Raises:
            AnsibleFailJson: If an incorrect import type is specified.
        Description:
            This function parses the playbook configuration to extract information related to image
            import, tagging, distribution, and activation. It stores these details in the 'want' dictionary
            for later use in the Ansible module.
        """

        want = {}
        want["application_queuing_details"] = config.get("application_queuing_details")
        want["application_set_details"] = config.get("application_set_details")
        want["application_details"] = config.get("application_details")
        want["application_policy_details"] = config.get("application_policy_details")

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_queuing_profile_details(self, name):
        """
        Retrieves the details of an application queuing profile by its name.
        Description:
            This method queries the Cisco Catalyst Center API to check if a queuing profile with the specified name exists. 
            It fetches the profile details if available. If the profile does not exist or an error occurs, the method logs 
            the issue and returns default values indicating that the profile was not found.
        Parameters:
            name (str): The name of the queuing profile to retrieve.
        Returns:
            tuple: A tuple containing:
                - queuing_profile_exists (bool): Indicates whether the queuing profile exists.
                - current_queuing_profile (dict): A dictionary containing the details of the queuing profile, or an 
                empty dictionary if the profile does not exist.
        Raises:
            Exception: Logs the error and updates the status if an API call fails or an unexpected issue occurs.
        """

        queuing_profile_exists = False
        current_queuing_profile = {}

        try:
            params = dict(name=name)
            response = self.dnac._exec(
                family="application_policy",
                function='get_application_policy_queuing_profile',
                params=params
            )
            self.log("Received API response from 'get_application_policy_queuing_profile': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("Unexpected response received:", "ERROR")
                raise Exception

            if not response.get("response"):
                self.log("empty response {0}".format(response))
                return queuing_profile_exists, current_queuing_profile

            current_queuing_profile = response.get("response")
            queuing_profile_exists = True
            self.log("got the details for queuing_profile_exists: {0} and  current_queuing_profile: {1}".format(queuing_profile_exists, current_queuing_profile))
            return queuing_profile_exists, current_queuing_profile

        except Exception as e:
            self.status = "failed"
            self.msg = "".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_application_set_details(self, name):
        """
        Retrieves the details of an application set by its name.
        Description:
            This method queries the Cisco Catalyst Center API to determine if an application set with the specified 
            name exists. It fetches the details of the application set if available. If the application set does not 
            exist or an error occurs, the method logs the issue and either raises an exception or returns default values 
            indicating that the application set was not found.
        Parameters:
            name (str): The name of the application set to retrieve.
        Returns:
            tuple: A tuple containing:
                - application_set_exists (bool): Indicates whether the application set exists.
                - current_application_set (dict): A dictionary containing the details of the application set, or an 
                empty dictionary if the application set does not exist.
        Raises:
            Exception: If the API response is unexpected or indicates failure, an exception is raised, and the 
            status is updated to "failed".
        """

        application_set_exists = False
        current_application_set = {}
        try:
            
            response = self.dnac._exec(
                family="application_policy",
                function='get_application_sets',
                params={"name": name}
            )
            self.log("Received API response from 'get_application_sets': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("Unexpected response received:", "ERROR")
                raise Exception

            if not response.get("response"):
                self.log("empty response {0}".format(response))
                return application_set_exists, current_application_set

            current_application_set = response.get("response")
            application_set_exists = True
            self.log("got the details for queuing_profile_exists: {0} and  current_application_set: {1}".format(application_set_exists, current_application_set))
            return application_set_exists, current_application_set

        except Exception as e:
            self.status = "failed"
            self.msg = "".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_application_set_id(self, name):
        """
        Retrieves the details of an application set by its name.
        Description:
            This method queries the Cisco Catalyst Center API to determine if an application set with the specified 
            name exists. It fetches the details of the application set if available. If the application set does not 
            exist or an error occurs, the method logs the issue and either raises an exception or returns default values 
            indicating that the application set was not found.
        Parameters:
            name (str): The name of the application set to retrieve.
        Returns:
            tuple: A tuple containing:
                - application_set_exists (bool): Indicates whether the application set exists.
                - current_application_set (dict): A dictionary containing the details of the application set, or an 
                empty dictionary if the application set does not exist.
        Raises:
            Exception: If the API response is unexpected or indicates failure, an exception is raised, and the 
            status is updated to "failed".
        """

        application_set_id = ''
        try:
            
            response = self.dnac._exec(
                family="application_policy",
                function='get_application_sets',
                params={"name": name}
            )
            self.log("Received API response from 'get_application_sets': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("Unexpected response received:", "ERROR")
                raise Exception

            if not response.get("response"):
                self.log("empty response {0}".format(response))
                raise Exception("No application set found in the Cisco Catalyst Center")

            current_application_set = response.get("response")
            application_set_id = current_application_set[0].get('id')

        except Exception as e:
            self.status = "failed"
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

        return application_set_id

    def get_application_details(self, name):
        """
        Retrieve the details of a specific application by its name.

        Parameters:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            name (str): The name of the application to retrieve.

        Returns:
            tuple: A tuple containing:
                - application_exists (bool): Indicates whether the application exists.
                - current_application (dict): The details of the application if found, otherwise an empty dictionary.

        Description:
            This function fetches the details of a specific application using the Cisco Catalyst Center API. It sends 
            a request to retrieve the application data by specifying its name along with additional parameters for 
            attributes, offset, and limit. If the response contains the application details, they are returned along 
            with a flag indicating the existence of the application. In case of an error or unexpected response, the 
            function logs the error, updates the status, and handles the exception gracefully.
        """
        application_exists = False
        current_application = {}
        try:
            
            response = self.dnac._exec(
                family="application_policy",
                function='get_applications',
                params={'attributes': "application", 'name': name, 'offset': 1, 'limit': 500}
            )
            self.log("Received API response from 'get_applications': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("Unexpected response received:", "ERROR")
                raise Exception

            if not response.get("response"):
                self.log("empty response {0}".format(response))
                return application_exists, current_application

            current_application = response.get("response")
            application_exists = True
            self.log("got the details for application_exists: {0} and  current_application_set: {1}".format(application_exists, current_application))
            return application_exists, current_application

        except Exception as e:
            self.status = "failed"
            self.msg = "".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_application_details_v1(self):
        """
        Retrieve the details of applications from Cisco Catalyst Center.

        Parameters:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.

        Returns:
            dict: A dictionary containing the details of the applications retrieved from Cisco Catalyst Center.

        Description:
            This function fetches the details of applications using the Cisco Catalyst Center API. It sends a request 
            to retrieve application data with specified attributes, offset, and limit. If a response is received, it 
            extracts the application details and logs the data. In case the response is empty, the function logs a 
            message and returns an empty dictionary.
        """
        current_application = {}

        try:
            # Fetching application data
            response = self.dnac._exec(
                family="application_policy",
                function="get_applications",
                params={"attributes": "application", "offset": 1, "limit": 500}
            )

            self.log("Received API response from 'get_applications': {0}".format(response), "DEBUG")

            # Check if the response contains data
            if not response.get("response"):
                self.log("Empty response received: {0}".format(response))
                return current_application

            current_application = response.get("response")

            self.log(
                "Retrieved application details successfully. Application Data: {0}".format(current_application),
                "DEBUG"
            )
            return current_application

        except Exception as e:
            self.status = "failed"
            self.msg = "Error occurred while fetching application details: {0}".format(str(e))
            self.result["response"] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_application_policy_details(self, name):
        """
        Get application policy details for the specified policy name.

        Parameters:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            name (str): The name of the application policy to retrieve.

        Returns:
            tuple: A tuple containing:
                - application_policy_exists (bool): Indicates whether the application policy exists.
                - current_application_policy (dict): The details of the application policy if found, otherwise an empty dictionary.

        Description:
            This function interacts with the Cisco Catalyst Center API to retrieve the details of an application policy 
            specified by its name. It sends an API request to fetch the policy details and processes the response. 
            If the response contains the policy details, they are returned along with a flag indicating its existence.
            In case of an exception, the function updates the status and logs an appropriate error message.
        """
        application_policy_exists = False
        current_application_policy = {}
        try:
            
            response = self.dnac._exec(
                family="application_policy",
                function='get_application_policy',
                params={"policyScope": name}
            )
            self.log("Received API response from 'get_application_sets': {0}".format(str(response)), "DEBUG")

            if not response:
                self.log("Unexpected response received:", "ERROR")
                raise Exception

            if not response.get("response"):
                self.log("empty response {0}".format(response))
                return application_policy_exists, current_application_policy

            current_application_policy = response.get("response")
            application_policy_exists = True
            self.log("got the details for queuing_profile_exists: {0} and  current_application_policy: {1}".format(application_policy_exists, current_application_policy))
            return application_policy_exists, current_application_policy

        except Exception as e:
            self.status = "failed"
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_have(self):
        """
        Retrieve and store various software image and device details based on user-provided information.
        Returns:
            self: The current instance of the class with updated 'have' attributes.
        Raises:
            AnsibleFailJson: If required image or device details are not provided.
        Description:
            This function populates the 'have' dictionary with details related to software images, site information,
            device families, distribution devices, and activation devices based on user-provided data in the 'want' dictionary.
            It validates and retrieves the necessary information from Cisco Catalyst Center to support later actions.
        """
        have = {}
        if self.want.get("application_queuing_details"):
            self.log("inside application_queuing_details")
            application_queuing_details = self.want.get("application_queuing_details")
            for detail in application_queuing_details:
                if detail.get("profile_name"):
                    application_queuing_name = detail.get("profile_name")
                    queuing_profile_exists, current_queuing_profile = self.get_queuing_profile_details(application_queuing_name)
                    have["current_queuing_profile"] = current_queuing_profile
                    have["queuing_profile_exists"] = queuing_profile_exists

        if self.want.get("application_set_details"):
            application_set_details = self.want.get("application_set_details")[0]
            if application_set_details.get("application_set_name"):
                application_set_name = application_set_details.get("application_set_name")
                application_set_exists, current_application_set = self.get_application_set_details(application_set_name)
                have["current_application_set"] = current_application_set
                have["application_set_exists"] = application_set_exists

        if self.want.get("application_policy_details"):
            application_policy_details = self.want.get("application_policy_details")
            application_policy_name = self.want.get("application_policy_details", {}).get("application_policy_name")
            self.log(application_policy_name)

            if not application_policy_name:
                self.status = "failed"
                self.msg = (
                    "The following parameter(s): 'name' could not be found  and are mandatory to create application policy ."
                )
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()

            if application_policy_details.get("application_queuing_profile_name"):
                queuing_profile_name = application_policy_details.get("application_queuing_profile_name")
                queuing_profile_exists, current_queuing_profile = self.get_queuing_profile_details(queuing_profile_name)
                have["current_queuing_profile"] = current_queuing_profile
                have["queuing_profile_exists"] = queuing_profile_exists

            if application_policy_details.get("application_policy_name"):
                application_policy_name = application_policy_details.get("application_policy_name")
                self.log(application_policy_name)
                application_policy_exists, current_application_policy = self.get_application_policy_details(application_policy_name)
                have["current_application_policy"] = current_application_policy
                have["application_policy_exists"] = application_policy_exists

        if self.want.get("application_details"):
            self.log("inside application")
            application_details = self.want.get("application_details")
            self.log(application_details)

            if application_details.get("application_name"):
                application_name = application_details.get("application_name")
                application_exists, current_application = self.get_application_details(application_name)
                have["current_application"] = current_application
                have["application_exists"] = application_exists

            if application_details.get("application_set_name"):
                application_set_name = application_details.get("application_set_name")
                application_set_exists, current_application_set = self.get_application_set_details(application_set_name)
                have["current_application_set"] = current_application_set
                have["application_set_exists"] = application_set_exists

        self.have = have
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")

        return self

    def get_diff_merged(self, config):
        """
        Get application queuing details and then trigger xxxxxxxxxxx details followed by xxxxxxx details and xxxxxxxx details if specified in the playbook.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing tagging, distribution, and activation details.
        Returns:
            self: The current instance of the class with updated 'result' and 'have' attributes.
        Description:
            This function checks the provided playbook configuration for tagging, distribution, and activation details. It
            then triggers these operations in sequence if the corresponding details are found in the configuration.The
            function monitors the progress of each task and updates the 'result' dictionary accordingly. If any of the
            operations are successful, 'changed' is set to True.
        """

        self.config = config

        if config.get("application_queuing_details"):
            self.get_diff_queuing_profile().check_return_status()

        if config.get("application_set_details"):
            self.get_diff_application_set().check_return_status()

        if config.get("application_details"):
            self.get_diff_application().check_return_status()

        if config.get("application_policy_details"):
            self.get_diff_application_policy().check_return_status()
        
    def get_diff_application_policy(self):

        application_policy_details = self.have

        if application_policy_details.get("application_policy_exists") == False:
            self.create_application_policy()
            return self

        req_application_policy_details = self.config.get("application_policy_details")
        application_policy_name = self.want.get("application_policy_details", {}).get("application_policy_name")
        site_names = req_application_policy_details.get("site_name")
        site_ids = []
        for site_name in site_names:
            site_exists, site_id = self.get_site_id(site_name)
            site_ids.append(site_id)
        application_set_names = req_application_policy_details.get("clause")
        application_queuing_profile_name = req_application_policy_details.get("application_queuing_profile_name")
        queuing_profile_id = application_policy_details.get('current_queuing_profile', [])[0].get('id', None)
        current_application_policy = application_policy_details.get("current_application_policy")

        self.log(req_application_policy_details)
        # Initialize flags
        is_update_required_for_queuing_profile = False
        is_update_required_for_site = False

        no_update_require = []
        other_check_names = ["application_queuing_profile", "site_name"] 
        final_app_set_payload = []
        # Check if the queuing profile name exists in current_application_policy
        for contract in current_application_policy:
            if 'contract' in contract and contract['contract']:
                current_application_policy_queuing_id = contract.get("id")
                advanced_policy_scope_for_queuing_profile = contract.get("advancedPolicyScope").get("id")
                advanced_policy_scope_element_for_queuing_profile = contract.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("id")
                name = contract.get("name")
                if application_queuing_profile_name not in name:
                    is_update_required_for_queuing_profile = True
                    break

        # Check if the site IDs match
        for application_policy in current_application_policy:
            curent_site_ids = application_policy.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("groupId")
            # Compare the site_ids and curent_site_ids
            if set(site_ids) != set(curent_site_ids):
                is_update_required_for_site = True
                break

        if is_update_required_for_site or is_update_required_for_queuing_profile:
            self.log("update required for queuing profile" if is_update_required_for_queuing_profile else "update required for site")
            group_id = site_ids if is_update_required_for_site else curent_site_ids

            payload = {
                    "id": current_application_policy_queuing_id,
                    "name": f"{application_policy_name}_{application_queuing_profile_name}",
                    "deletePolicyStatus": current_application_policy[0].get("deletePolicyStatus"),
                    "policyScope": current_application_policy[0].get("policyScope"),
                    "priority": current_application_policy[0].get("priority"),
                    "advancedPolicyScope": {
                        "id": advanced_policy_scope_for_queuing_profile,
                        "name": application_policy_name,
                        "advancedPolicyScopeElement": [
                            {
                                "id": advanced_policy_scope_element_for_queuing_profile,
                                "groupId": group_id,
                                "ssid": []
                            }
                        ]
                    },
                    "contract": {
                        "idRef": queuing_profile_id
                    }
                }
            final_app_set_payload.append(payload)
            self.log(json.dumps(payload, indent=4))
        else:
            self.log("no update is required for queuing profile")
            no_update_require.append("application_queuing_profile")

        if is_update_required_for_site is True:
            self.log("update required for site")
        else:
            self.log("no update is required for site")
            no_update_require.append("site_name")

        update_not_required = True
        for check in other_check_names:
            if check not in no_update_require:
                update_not_required = False
                break
        
        want_business_relevant_set_name, want_business_irrelevant_set_name, want_default_set_name = [], [], []
        have_business_relevant_set_name, have_business_irrelevant_set_name, have_default_set_name = [], [], []
        final_business_relevant_set_name, final_business_irrelevant_set_name, final_default_set_name = [], [], []

        # Application data (replace with actual data or mock data)
        application_set_names = req_application_policy_details.get("clause")

        total_current_app_set = []
        total_want_app_set = []
        # Populate the lists based on relevance
        for item in application_set_names:
            for relevance in item['relevance_details']:
                if relevance['relevance'] == 'BUSINESS_RELEVANT':
                    want_business_relevant_set_name.extend(relevance['application_set_name'])
                    total_want_app_set.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'BUSINESS_IRRELEVANT':
                    want_business_irrelevant_set_name.extend(relevance['application_set_name'])
                    total_want_app_set.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'DEFAULT':
                    want_default_set_name.extend(relevance['application_set_name'])
                    total_want_app_set.extend(relevance['application_set_name'])

        self.log(f"Wanted Business Irrelevant Set: {want_business_irrelevant_set_name}")
        self.log(f"Wanted Business Relevant Set: {want_business_relevant_set_name}")
        self.log(f"Wanted Default Set: {want_default_set_name}")


        # Populate current application set names
        for application_sets in current_application_policy:
            clause = application_sets.get("exclusiveContract", {}).get("clause")
            if clause and clause[0].get("relevanceLevel") is not None:
                current_relevance_type = clause[0].get("relevanceLevel")

                # Process Business Relevant
                if current_relevance_type == "BUSINESS_RELEVANT":
                    full_name = application_sets.get("name") 
                    policy_name = application_sets.get("policyScope") + '_'
                    app_set_name = full_name.replace(policy_name, "")
                    have_business_relevant_set_name.append(app_set_name)
                    total_current_app_set.append(app_set_name)

                    for set_name in want_business_relevant_set_name:
                        if set_name in application_sets.get("name"):
                            self.log(f"No update required for: {set_name}")


                # Process Business Irrelevant
                elif current_relevance_type == "BUSINESS_IRRELEVANT":
                    full_name = application_sets.get("name") 
                    policy_name = application_sets.get("policyScope") + '_'
                    app_set_name = full_name.replace(policy_name, "")
                    have_business_irrelevant_set_name.append(app_set_name)
                    total_current_app_set.append(app_set_name)

                    for set_name in want_business_irrelevant_set_name:
                        if set_name in application_sets.get("name"):
                            self.log(f"No update required for: {set_name}")

                # Process Default
                elif current_relevance_type == "DEFAULT":
                    full_name = application_sets.get("name") 
                    policy_name = application_sets.get("policyScope") + '_'
                    app_set_name = full_name.replace(policy_name, "")
                    have_default_set_name.append(app_set_name)
                    total_current_app_set.append(app_set_name)

                    for set_name in want_default_set_name:
                        if set_name in application_sets.get("name"):
                            self.log(f"No update required for: {set_name}")

        self.log(f"Total Current Application Set: {total_current_app_set}")
        self.log(f"Total Want Application Set: {total_want_app_set}")


        # Compare sets
        current_set = set(total_current_app_set)
        want_set = set(total_want_app_set)

        # Check if anything extra is in the 'want' set
        extra_in_want = want_set - current_set

        if extra_in_want:
            self.status = "failed"
            self.msg = "no extra application sets can be added to the application policy".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

            #fail the code
        else:
            self.log("Comparison passed. No extra items in want.")

        # List of all want and have lists
        want_lists = [
            (want_business_relevant_set_name, have_business_relevant_set_name, final_business_relevant_set_name),
            (want_business_irrelevant_set_name, have_business_irrelevant_set_name, final_business_irrelevant_set_name),
            (want_default_set_name, have_default_set_name, final_default_set_name)
        ]

        # Compare and append missing elements to the final lists
        for want_item, have_item, final_item in want_lists:
            for w in want_item:
                if w not in have_item:
                    final_item.append(w)  # Add missing item from "want"
            if not want_item:  # If the "want" list is empty, ensure "have" is added to final
                final_item.extend([item for item in have_item if item not in final_item])

        # Ensure the default list is empty if no relevant/default values are there
        if not want_default_set_name:
            final_default_set_name = []
        if not want_business_relevant_set_name:
            final_business_relevant_set_name = []
        if not want_business_irrelevant_set_name:
            final_business_irrelevant_set_name = []

        # self.log the final lists
        self.log(f"have Business Relevant: {have_business_relevant_set_name}")
        self.log(f"have Business Irrelevant: {have_business_irrelevant_set_name}")
        self.log(f"have Default: {have_default_set_name}")

        self.log(f"Final Business Relevant: {final_business_relevant_set_name}")
        self.log(f"Final Business Irrelevant: {final_business_irrelevant_set_name}")
        self.log(f"Final Default: {final_default_set_name}")

        # Compute the differences
        final_want_business_relevant = []
        final_want_business_irrelevant = []
        final_want_default = []

        # Check if the value is not in all three lists
        for item in have_business_relevant_set_name:
            if item not in final_business_relevant_set_name and \
            item not in final_business_irrelevant_set_name and \
            item not in final_default_set_name:
                final_want_business_relevant.append(item)

        for item in have_business_irrelevant_set_name:
            if item not in final_business_relevant_set_name and \
            item not in final_business_irrelevant_set_name and \
            item not in final_default_set_name:
                final_want_business_irrelevant.append(item)

        for item in have_default_set_name:
            if item not in final_business_relevant_set_name and \
            item not in final_business_irrelevant_set_name and \
            item not in final_default_set_name:
                final_want_default.append(item)


        # Log the results
        self.log(f"Final want Business Relevant (Diff): {final_want_business_relevant}")
        self.log(f"Final want Business Irrelevant (Diff): {final_want_business_irrelevant}")
        self.log(f"Final want Default (Diff): {final_want_default}")

        if update_not_required :
            if not (final_business_irrelevant_set_name or final_business_relevant_set_name or final_default_set_name):
                self.log("no update required for application policy")
                self.status = "success"
                self.result['changed'] = False
                self.msg = "application '{0}' does not need any update. ".format(application_policy_name)
                self.result['msg'] = self.msg
                self.result['response'] = self.msg
                self.log(self.msg, "INFO")
                return self

        for application_sets in current_application_policy:
            group_id = site_ids if is_update_required_for_site else curent_site_ids
            for app_set in final_business_relevant_set_name + final_business_irrelevant_set_name + final_default_set_name:
                if app_set in final_business_relevant_set_name:
                    relevance_level = "BUSINESS_RELEVANT"
                elif app_set in final_business_irrelevant_set_name:
                    relevance_level = "BUSINESS_IRRELEVANT"
                elif app_set in final_default_set_name:
                    relevance_level = "DEFAULT"
                
                if relevance_level and app_set in application_sets.get("name"):
                    self.log(app_set)
                    app_set_payload = {
                        "id": application_sets.get("id"),
                        "name": f"{application_sets.get('policyScope')}_{app_set}",
                        "deletePolicyStatus": application_sets.get("deletePolicyStatus"),
                        "policyScope": application_sets.get('policyScope'),
                        "priority": application_sets.get('priority'),
                        "advancedPolicyScope": {
                            "id": application_sets.get("advancedPolicyScope").get("id"),
                            "name": application_sets.get("advancedPolicyScope").get("name"),
                            "advancedPolicyScopeElement": [
                                {
                                    "id": application_sets.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("id"),
                                    "groupId": group_id,
                                    "ssid": []
                                }
                            ]
                        },
                        "exclusiveContract": {
                            "id": application_sets.get("exclusiveContract").get("id"),
                            "clause": [
                                {
                                    "id": application_sets.get("exclusiveContract").get("clause")[0].get("id"),
                                    "type": application_sets.get("exclusiveContract").get("clause")[0].get("type"),
                                    "relevanceLevel": relevance_level
                                }
                            ]
                        },
                        "producer": {
                            "id": application_sets.get("producer").get("id"),
                            "scalableGroup": [
                                {
                                    "idRef": application_sets.get("producer").get("scalableGroup")[0].get("idRef")
                                }
                            ]
                        }
                    }
                    final_app_set_payload.append(app_set_payload)

        for application_sets in current_application_policy:
            if is_update_required_for_site == True:
                group_id = site_ids if is_update_required_for_site else curent_site_ids
                for app_set in final_want_business_relevant + final_want_business_irrelevant + final_want_default:
                    if app_set in final_want_business_relevant:
                        relevance_level = "BUSINESS_RELEVANT"
                    elif app_set in final_want_business_irrelevant:
                        relevance_level = "BUSINESS_IRRELEVANT"
                    elif app_set in final_want_default:
                        relevance_level = "DEFAULT"
                    
                    if relevance_level and app_set in application_sets.get("name"):
                        self.log(app_set)
                        app_set_payload = {
                            "id": application_sets.get("id"),
                            "name": f"{application_sets.get('policyScope')}_{app_set}",
                            "deletePolicyStatus": application_sets.get("deletePolicyStatus"),
                            "policyScope": application_sets.get('policyScope'),
                            "priority": application_sets.get('priority'),
                            "advancedPolicyScope": {
                                "id": application_sets.get("advancedPolicyScope").get("id"),
                                "name": application_sets.get("advancedPolicyScope").get("name"),
                                "advancedPolicyScopeElement": [
                                    {
                                        "id": application_sets.get("advancedPolicyScope").get("advancedPolicyScopeElement")[0].get("id"),
                                        "groupId": group_id,
                                        "ssid": []
                                    }
                                ]
                            },
                            "exclusiveContract": {
                                "id": application_sets.get("exclusiveContract").get("id"),
                                "clause": [
                                    {
                                        "id": application_sets.get("exclusiveContract").get("clause")[0].get("id"),
                                        "type": application_sets.get("exclusiveContract").get("clause")[0].get("type"),
                                        "relevanceLevel": relevance_level
                                    }
                                ]
                            },
                            "producer": {
                                "id": application_sets.get("producer").get("id"),
                                "scalableGroup": [
                                    {
                                        "idRef": application_sets.get("producer").get("scalableGroup")[0].get("idRef")
                                    }
                                ]
                            }
                        }
                        final_app_set_payload.append(app_set_payload)

        self.log(json.dumps(final_app_set_payload, indent=4))
        try:
            response = self.dnac._exec(
                family="application_policy",
                function='application_policy_intent',
                op_modifies= True,
                params= {'updateList': final_app_set_payload,}
                )

            self.log(f"Received API response from 'application_policy_intent' for Update: {response}", "DEBUG")
            self.check_tasks_response_status(response, "application_policy_intent")

            if self.status not in ["failed", "exited"]:
                self.log("application policy '{0}' updated successfully.".format(application_policy_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application policy '{0}' updated successfully.".format(application_policy_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "update of the application policy failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()


    def create_application_policy(self):
        """
        Create an application policy and trigger its deployment details based on the configuration provided in the playbook.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self: The current instance of the class with updated 'result', 'status', and 'msg' attributes.

        Description:
            This function creates an application policy in the Catalyst Center by processing the configuration details 
            provided in the playbook. It retrieves site information, identifies application queuing profiles, and 
            categorizes application sets based on relevance levels (BUSINESS_RELEVANT, BUSINESS_IRRELEVANT, and DEFAULT). 
            The application sets are mapped to their IDs, and a payload is generated for API submission. The function 
            then sends a request to create the application policy and validates the response. 

            In case of an error or failure in creation, appropriate error messages are logged, and the function updates 
            the status and result attributes.
        """

        new_application_policy_details = self.config.get("application_policy_details")
        application_policy_name = self.want.get("application_policy_details", {}).get("application_policy_name")
        site_names = new_application_policy_details.get("site_name")
        site_ids = []
        for site_name in site_names:
            site_exists, site_id = self.get_site_id(site_name)
            site_ids.append(site_id)
        application_policy_details = self.have
        application_set_names = new_application_policy_details.get("clause")
        application_queuing_profile_name = new_application_policy_details.get("application_queuing_profile_name")
        queuing_profile_id = application_policy_details.get('current_queuing_profile', [])[0].get('id', None)

        self.log(application_queuing_profile_name)
        self.log(queuing_profile_id)
        self.log(new_application_policy_details)
        # Initialize empty lists for each relevance
        business_relevant_set_name, business_relevant_set_id = [], []
        business_irrelevant_set_name, business_irrelevant_set_id = [], []
        default_set_name, default_set_id = [], []

        # Populate the lists based on relevance
        for item in application_set_names:
            for relevance in item['relevance_details']:
                if relevance['relevance'] == 'BUSINESS_RELEVANT':
                    business_relevant_set_name.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'BUSINESS_IRRELEVANT':
                    business_irrelevant_set_name.extend(relevance['application_set_name'])
                elif relevance['relevance'] == 'DEFAULT':
                    default_set_name.extend(relevance['application_set_name'])

        # Get application set IDs for business_relevant
        for app_set_name in business_relevant_set_name:
            app_set_id = self.get_application_set_id(app_set_name)
            if app_set_id:
                business_relevant_set_id.append({"name": app_set_name, "id": app_set_id})
            else:
                self.log(f"No app set found for {app_set_name}")

        # Get application set IDs for business_irrelevant
        for app_set_name in business_irrelevant_set_name:
            app_set_id = self.get_application_set_id(app_set_name)
            if app_set_id:
                business_irrelevant_set_id.append({"name": app_set_name, "id": app_set_id})
            else:
                self.log(f"No app set found for {app_set_name}")

        # Get application set IDs for default
        for app_set_name in default_set_name:
            app_set_id = self.get_application_set_id(app_set_name)
            if app_set_id:
                default_set_id.append({"name": app_set_name, "id": app_set_id})
            else:
                self.log(f"No app set found for {app_set_name}")

        # Log the final lists
        self.log(f"Business Relevant Set IDs: {business_relevant_set_id}")
        self.log(f"Business Irrelevant Set IDs: {business_irrelevant_set_id}")
        self.log(f"Default Set IDs: {default_set_id}")

        # Determine the deletePolicyStatus
        policy_status = new_application_policy_details.get("policy_status")
        delete_policy_status = {
            "deployed": "NONE",
            "deleted": "DELETED",
            "restored": "RESTORED"
        }.get(policy_status, "NONE")

        # Map relevance to application set IDs
        relevance_map = {
            "BUSINESS_RELEVANT": business_relevant_set_id,
            "BUSINESS_IRRELEVANT": business_irrelevant_set_id,
            "DEFAULT": default_set_id
        }

        # Generate payload
        payload = []
        # for queuing profile
        payload.append({
                    "name": f"{application_policy_name}_{application_queuing_profile_name}",
                    "deletePolicyStatus": delete_policy_status,
                    "policyScope": f"{application_policy_name}",
                    "priority": "100",
                    "advancedPolicyScope": {
                        "name": f"{application_policy_name}",
                        "advancedPolicyScopeElement": [
                            {
                                "groupId": site_ids,
                                "ssid": []
                            }
                        ]
                    },
                    "contract": {
                        "idRef": queuing_profile_id
                    }
                },
        )

        for relevance_detail in new_application_policy_details['clause'][0]['relevance_details']:
            relevance_level = relevance_detail['relevance']
            application_set_names = relevance_detail['application_set_name']
            
            for app_set_name in application_set_names:
                # Find the matching application set ID
                matching_set = next((item for item in relevance_map[relevance_level] if item['name'] == app_set_name), None)
                if not matching_set:
                    continue
                
                # Append the policy details to the payload
                payload.append({
                    "name": f"{application_policy_name}_{app_set_name}",
                    "deletePolicyStatus": delete_policy_status,
                    "policyScope": f"{application_policy_name}",
                    "priority": "100",
                    "advancedPolicyScope": {
                        "name": f"{application_policy_name}",
                        "advancedPolicyScopeElement": [
                            {
                                "groupId": [site_id],
                                "ssid": []
                            }
                        ]
                    },
                    "exclusiveContract": {
                        "clause": [
                            {
                                "type": "BUSINESS_RELEVANCE",
                                "relevanceLevel": relevance_level
                            }
                        ]
                    },
                    "producer": {
                        "scalableGroup": [
                            {
                                "idRef": matching_set['id']
                            }
                        ]
                    }
                })

        self.log(json.dumps(payload, indent=4))

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='application_policy_intent',
                op_modifies= True,
                params= {'createList': payload,}
                )

            self.log(f"Received API response from 'application_policy_intent' for creation: {response}", "DEBUG")
            self.check_tasks_response_status(response, "application_policy_intent")

            if self.status not in ["failed", "exited"]:
                self.log("application policy '{0}' created successfully.".format(application_policy_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application policy '{0}' created successfully.".format(application_policy_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "creation of the application policy failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_diff_application(self):
        """
        Retrieve and update differences between current and required application configurations.

        Parameters:
            self (object): An instance of the class for interacting with Cisco Catalyst Center.

        Returns:
            self: The updated instance with 'status', 'msg', and 'result' attributes.

        Description:
            Compares the existing application details ('have') with the desired configuration ('want') and updates
            the application if discrepancies are found. Handles mandatory field validation, constructs the update 
            payload, logs required actions, and sends an API request to apply changes.
        """

        application_name = self.want.get("application_details", {}).get("application_name")
        application_set_name = self.want.get("application_details").get("application_set_name")
        if application_name is None:
            self.status = "failed"
            self.msg = "mandatory field 'application_name' is missing"
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

        application_details = self.have
        required_application_details = self.want.get("application_details")

        if application_details.get("application_set_exists") == False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = " the application set '{0}' is not avalable in the Cisco catalyst center".format(application_set_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        if application_details.get("application_exists") == False:
            self.create_application()
            return self

        current_application_details = application_details.get("current_application")[0]

        current_application_set = application_details.get("current_application_set")

        application_set_id = None
        if current_application_set and isinstance(current_application_set, list) and len(current_application_set) > 0:
            application_set_id = current_application_set[0].get("id")

        application_name = current_application_details.get("name")
        self.log(current_application_details)
        if required_application_details.get("application_name") != current_application_details.get("name"):
            self.log("application name cant be updated")

        # Define the mappings for comparison
        fields_to_check = {
            "description": "longDescription",
            "helpstring": "helpString",
            "traffic_class": "trafficClass",
            "server_name": "serverName"
        }

        update_required_keys = []

        # Check and log messages if update not required
        for required_key, current_key in fields_to_check.items():
            # Skip if any field is None or not present
            required_value = required_application_details.get(required_key)
            current_value = current_application_details.get("networkApplications")[0].get(current_key)

            if current_value is None:
                if required_value is not None:
                    self.log(f"Update required for {required_key} as current value is None.")
                    update_required_keys.append(required_key)
                else:
                    self.log(f"Skipping {required_key} as both values are None.")
                continue

            if required_value == current_value:
                self.log(f"Update not required for {required_key}")
            else:
                self.log(f"Update required for {required_key}")
                update_required_keys.append(required_key)

        # Check for application_set_id
        self.log(current_application_details)
        self.log(current_application_details.get("parentScalableGroup").get("idRef"))

        if application_set_id == current_application_details.get("parentScalableGroup").get("idRef") or application_set_id is None:
            self.log("update not required for application_set")
            application_set_id = current_application_details.get("parentScalableGroup").get("idRef")
        else:
            self.log("update required for application set")
            update_required_keys.append("application_set")

        if not update_required_keys:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "application '{0}' does not need any update. ".format(application_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        #construct payload for Updation
        network_application_payload = {
            "id": current_application_details.get("networkApplications")[0].get("id"),
            "applicationSubType": current_application_details.get("networkApplications")[0].get("applicationSubType"),
            "applicationType": current_application_details.get("networkApplications")[0].get("applicationType"),
            "categoryId": current_application_details.get("networkApplications")[0].get("categoryId"),
            "displayName": current_application_details.get("networkApplications")[0].get("displayName"),
            "helpString": required_application_details.get("helpstring") if "helpstring" in update_required_keys else current_application_details.get("networkApplications")[0].get("helpString"),
            "longDescription": required_application_details.get("description") if "description" in update_required_keys else current_application_details.get("networkApplications")[0].get("longDescription"),
            "name": current_application_details.get("networkApplications")[0].get("name"),
            "popularity": current_application_details.get("networkApplications")[0].get("popularity"),
            "rank": required_application_details.get("rank") if "rank" in update_required_keys else current_application_details.get("networkApplications")[0].get("rank"),
            "selectorId": current_application_details.get("networkApplications")[0].get("selectorId"),
            "trafficClass": required_application_details.get("traffic_class") if "traffic_class" in update_required_keys else current_application_details.get("networkApplications")[0].get("trafficClass"),
        }

        if "server_name" in required_application_details:
            network_application_payload["serverName"] = required_application_details.get("server_name")
            if "serverName" in current_application_details.get("networkApplications")[0]:
                network_application_payload["serverName"] = current_application_details.get("networkApplications")[0].get("serverName")
        else:
          if "url" in required_application_details:
            network_application_payload["url"] = required_application_details.get("url")
          if "url" in current_application_details.get("networkApplications")[0]:
              network_application_payload["url"] = current_application_details.get("networkApplications")[0].get("url")
          if "app_protocol" in required_application_details:
                network_application_payload["appProtocol"] = required_application_details.get("app_protocol")
          if "appProtocol" in current_application_details.get("networkApplications")[0]:
              network_application_payload["appProtocol"] = current_application_details.get("networkApplications")[0].get("appProtocol")

        network_identity_setting = {}

        if "network_identity_setting" in required_application_details:
            network_identity_details = required_application_details["network_identity_setting"]

            key_mapping = {
                "protocol": "protocol",
                "port": "ports",
                "ip_subnet": "ipv4Subnet",
                "lower_Port": "lowerPort",
                "upper_port": "upperPort"
            }

            for source_key, target_key in key_mapping.items():
                if source_key in network_identity_details:
                    network_identity_setting[target_key] = network_identity_details[source_key]

        self.log(network_identity_setting)

        # Construct the full payload
        param = [
            {
                "id": current_application_details.get("id"),
                "instanceId": current_application_details.get("instanceId"),
                "displayName": current_application_details.get("displayName"),
                "instanceVersion": current_application_details.get("instanceVersion"),
                "name": current_application_details.get("name"),
                "namespace": current_application_details.get("namespace"),
                "networkApplications": [network_application_payload],
                "parentScalableGroup": {
                    "idRef": application_set_id
                },
                # Add "networkIdentity" only if the condition is met
                **(
                    {"networkIdentity": [network_identity_setting]}
                    if "network_identity_setting" in required_application_details
                    else {}
                ),
                "qualifier": current_application_details.get("qualifier"),
                "scalableGroupExternalHandle": current_application_details.get("scalableGroupExternalHandle"),
                "scalableGroupType": current_application_details.get("scalableGroupType"),
                "type": current_application_details.get("type"),
            }
        ]



        self.log(f"Payload for update application: {json.dumps(param, indent=4)}")

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='edit_applications',
                op_modifies= True,
                params= {"payload": param}
                )

            self.log(f"Received API response from 'edit_applications': {response}", "DEBUG")
            self.check_tasks_response_status(response, "edit_applications")

            if self.status not in ["failed", "exited"]:
                self.log("application '{0}' updated successfully.".format(application_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application '{0}' updated successfully.".format(application_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "updation of the application failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "updation of the application failed".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def create_application(self):
        """
        Create a new application in Cisco DNA Center.

        Parameters:
            self (object): An instance of the class for interacting with Cisco DNA Center.

        Returns:
            self: The updated instance with 'status', 'msg', and 'result' attributes.

        Description:
            This method creates a new application by comparing the desired configuration ('want') with the existing 
            application details ('have'). It checks for missing mandatory fields, validates the application type, 
            and constructs the payload for the application creation request. The method sends an API request to 
            Cisco DNA Center to create the application and logs success or failure. If any errors are encountered, 
            they are handled and returned with appropriate messages.
        """

        new_application_set_details = self.want
        application_set_name = new_application_set_details.get('application_details', {}).get('application_set_name')
        application_set_id = self.get_application_set_id(application_set_name)
        application_details = self.want.get("application_details")
        application_name = application_details.get("application_name")
        application_traffic_class = application_details.get("traffic_class")
        application_type = application_details.get("type")
        application_details_set = self.have
        get_application_set  = application_details.get("current_application_set")

        missing_fields = []

        if application_traffic_class is None:
            missing_fields.append("traffic_class")
        if application_name is None:
            missing_fields.append("application_name")
        if application_set_name is None:
            missing_fields.append("application_set_name")
        if application_type is None:
            missing_fields.append("type")

        if missing_fields:
            self.status = "failed"
            self.msg = f"As we need to create a new application - mandatory field(s) missing: {', '.join(missing_fields)}"
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()


        self.log(application_set_id)
        get_application_list = self.get_application_details_v1()
        self.log(get_application_list)
        category_id = None  # Default value

        for app in get_application_list:
            if app.get("parentScalableGroup", {}).get("idRef") == application_set_id:
                network_applications = app.get("networkApplications")
                if network_applications and isinstance(network_applications, list):
                    category_id = network_applications[0].get("categoryId")  # Access the first element
                break  # Exit the loop once a match is found


        supported_types = ["server_name", "url", "server_ip"]

        if application_details.get("type") not in ["server_name", "url", "server_ip"]:
            self.status = "failed"
            self.msg = f"Unsupported application type: '{application_type}'. Supported values are: {', '.join(supported_types)}."
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

        # Prepare common application data, ignoring optional fields if not provided
        network_application = {
            "applicationType": "CUSTOM",
            "trafficClass": application_details.get("traffic_class"),
            "categoryId": category_id,
            "type": "_server-ip" if application_details.get("type") == "server_ip" else
                    "_url" if application_details.get("type") == "url" else "_servername"
        }

        # Add optional fields if they exist in the application_details
        optional_fields = [
            ("ignore_conflict", "ignoreConflict"),
            ("rank", "rank"),
            ("engine_id", "engineId"),
            ("helpstring", "helpString"),
            ("description", "longDescription")
        ]

        for field, key in optional_fields:
            value = application_details.get(field)
            if value is not None:  # Only add to payload if the value exists
                network_application[key] = value if key not in ("rank", "engineId") else int(value)

        # Add specific fields for 'server_name', 'url', or 'server_ip'
        app_type = application_details.get("type")

        if app_type == "server_name":
            if application_details.get("server_name") is None:
                self.status = "failed"
                self.msg = ("server_name is required for the type - server_name")
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

            network_application["serverName"] = application_details.get("server_name")

        elif app_type == "url":
            if application_details.get("app_protocol") is None or application_details.get("url") is None:
                self.status = "failed"
                self.msg = ("app_protocol and url are required for the type - url")
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

            network_application["appProtocol"] = application_details.get("app_protocol")
            network_application["url"] = application_details.get("url")

        # Handle the conditional inclusion of `dscp` or `network_identity_setting` (or both)
        dscp = application_details.get("dscp")
        network_identity_setting = application_details.get("network_identity_setting", {})

        network_identity_list = None  # Default to None

        if app_type == "server_ip":
            if not dscp and not network_identity_setting:
                self.status = "failed"
                self.msg = ("Either 'dscp' or 'network_identity_setting' must be provided for the type - server_ip.")
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()


            # Add dscp if present
            if dscp:
                network_application["dscp"] = dscp

            # Add network_identity_setting if present
            if network_identity_setting:
                protocol = network_identity_setting.get("protocol")
                ports = network_identity_setting.get("port")

                # Raise an error if mandatory fields are missing
                if not protocol or not ports:
                    self.status = "failed"
                    self.msg = ("Both 'protocol' and 'ports' are required for the network identity in server_ip type.")
                    self.result['response'] = self.msg
                    self.log(self.msg, "ERROR")
                    self.check_return_status()

                # Prepare networkIdentity dictionary with mandatory and optional fields
                network_identity = {
                    "protocol": protocol,
                    "ports": str(ports)  # Ensure port is a string
                }

                # Optional fields for networkIdentity
                optional_network_identity_fields = [
                    ("ip_subnet", "ipv4Subnet"),
                    ("lower_port", "lowerPort"),
                    ("upper_port", "upperPort")
                ]

                for field, key in optional_network_identity_fields:
                    value = network_identity_setting.get(field)
                    if value is not None:
                        network_identity[key] = value

                # Include networkIdentity in the payload
                network_identity_list = [network_identity]

        # Prepare the rest of the payload
        param = {
            "name": application_details.get("application_name"),
            "parentScalableGroup": {
                "idRef": application_set_id
            },
            "scalableGroupType": "APPLICATION",
            "type": "scalablegroup",
            "networkApplications": [network_application],
        }

        # Add networkIdentity if it exists
        if network_identity_list:
            param["networkIdentity"] = network_identity_list
        self.log(param)
        try:
            response = self.dnac._exec(
                family="application_policy",
                function='create_applications',
                op_modifies= True,
                params = {"payload": [param]}
                )

            self.log(f"Received API response from 'create_applications': {response}", "DEBUG")
            self.check_tasks_response_status(response, "create_applications")

            if self.status not in ["failed", "exited"]:
                self.log("application '{0}' created successfully.".format(application_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application '{0}' created successfully.".format(application_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "creation of the application failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_diff_application_set(self):
        """
        Manages the creation of an application set by checking for its existence.

        Description:
            This method checks if an application set already exists using the `have` attribute. 
            If the application set exists, it logs the status and skips creation. If it does not 
            exist, the method calls `create_application_set` to create a new application set.

        Parameters:
            None: This method relies on the class instance's `have` attribute for determining the current state.

        Returns:
            self: The current instance of the class, updated with the result of the operation.

        Raises:
            None: All conditions and errors are handled internally.
        """

        application_set_details = self.have
        if application_set_details.get("application_set_exists") == True:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "application set already exist and hence cant be updated"
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        self.create_application_set()
        return self

    def create_application_set(self):
        """
        Creates a new application set in Cisco Catalyst Center.
        Description:
            This method retrieves the application set details from the `config` attribute and constructs a payload 
            required to create the application set. It then triggers the appropriate API call to create the application set 
            and monitors the task's response status. If the creation is successful, the method updates the status and logs 
            a success message.
        Parameters:
            None: The method uses the `config` attribute from the class instance to retrieve application set details.
        Returns:
            self: Returns the current instance of the class with updated attributes such as `status`, `result`, and `msg`.
        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """
        new_application_set_details = self.want
        application_set_name = new_application_set_details.get('application_details', {}).get('application_set_name')
        param = {"name":application_set_name}
        try:
            response = self.dnac._exec(
                family="application_policy",
                function='create_application_set',
                op_modifies= True,
                params = {"payload": [param]}
            )
            self.log(f"Received API response from 'create_application_set': {response}", "DEBUG")
            self.check_tasks_response_status(response, "create_application_policy_queuing_profile")

            if self.status not in ["failed", "exited"]:
                self.log("application set '{0}' created successfully.".format(application_set_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application set '{0}' created successfully.".format(application_set_name))
                self.result['response'] = self.msg
                return self

        except Exception as e:
            self.status = "failed"
            self.msg = "".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_diff_queuing_profile(self):
        """
        Creates a new application queuing profile based on the provided configuration.
        Description:
            This method retrieves queuing profile details from the `config` attribute and validates mandatory fields.
            It constructs the payload required for creating a queuing profile and triggers the appropriate API call 
            to Cisco Catalyst Center. The response from the API is logged for debugging and tracking purposes.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Raises:
            ValueError: If any mandatory fields (`profile_name`, `type`, or `tc_bandwidth_settings`) are missing 
            in the configuration.
        Returns:
            None: The method updates the system state by calling the API and logs the API response.
        """
        queuing_profile = self.have
        required_queuing_profile_details = self.want

        if queuing_profile.get("queuing_profile_exists") == False:
            self.create_queuing_profile()
            return self

        # queuing_profile = queuing_profile_details["current_queuing_profile"][0]
        # queuing_profile_id = queuing_profile_details["current_queuing_profile"][0]["id"]
        # input_details = required_queuing_profile_details["application_queuing_details"][0]
        # input_bandwidth_settings = input_details["bandwidth_settings"]["bandwidth_percentages"]
        # input_dscp_settings = input_details["dscp_settings"]

        required_details = required_queuing_profile_details['application_queuing_details'][0]
        want_bandwidth_settings = {
            key.upper(): value for key, value in required_details['bandwidth_settings']['bandwidth_percentages'].items()
        }

        want_dscp_settings = {key.upper(): value.upper() if isinstance(value, str) else value
                            for key, value in required_details['dscp_settings'].items()}


        # Current queuing profile bandwidth and DSCP settings
        have_bandwidth_settings = {
            tc['trafficClass']: tc['bandwidthPercentage']
            for tc in queuing_profile['current_queuing_profile'][0]['clause'][0]['interfaceSpeedBandwidthClauses'][0]['tcBandwidthSettings']
        }

        have_dscp_settings = {
            tc['trafficClass']: tc['dscp']
            for tc in queuing_profile['current_queuing_profile'][0]['clause'][1]['tcDscpSettings']
        }

        # Output the extracted data
        self.log("want Bandwidth Settings:")
        self.log(want_bandwidth_settings)

        self.log("\nhave Bandwidth Settings:")
        self.log(have_bandwidth_settings)

        self.log("\nwant DSCP Settings:")
        self.log(want_dscp_settings)

        self.log("\nhave DSCP Settings:")
        self.log(have_dscp_settings)

        # Initialize final dictionary
        final_want_bandwidth_dict = {}

        for traffic_class, want_value in want_bandwidth_settings.items():
            # Convert want_value to int for comparison
            want_value = int(want_value)

            if traffic_class in have_bandwidth_settings:
                have_value = have_bandwidth_settings[traffic_class]
                # Compare values
                if want_value == have_value:
                    final_want_bandwidth_dict[traffic_class] = have_value
                else:
                    final_want_bandwidth_dict[traffic_class] = want_value
            else:
                # If the traffic class is only in want
                final_want_bandwidth_dict[traffic_class] = want_value

        self.log("Final Want bandwidth Dict:")
        self.log(final_want_bandwidth_dict)

        final_want_dscp_dict = {}
        for traffic_class, want_value in want_dscp_settings.items():
            # Convert want_value to int for comparison
            want_value = int(want_value)

            if traffic_class in have_dscp_settings:
                have_value = have_dscp_settings[traffic_class]
                # Compare values
                if want_value == have_value:
                    final_want_dscp_dict[traffic_class] = have_value
                else:
                    final_want_dscp_dict[traffic_class] = want_value
            else:
                # If the traffic class is only in want
                final_want_dscp_dict[traffic_class] = want_value

        # Final result
        self.log("Final Want dscp Dict:")
        self.log(final_want_dscp_dict)

        id_bandwidth_mapping = {}
        id_dscp_mapping = {}

        # Navigate through the queuing profile structure
        current_profiles = queuing_profile.get('current_queuing_profile', [])

        for profile in current_profiles:
            for clause in profile.get('clause', []):
                if clause.get('type') == 'BANDWIDTH':
                    for interface_clause in clause.get('interfaceSpeedBandwidthClauses', []):
                        for bandwidth_setting in interface_clause.get('tcBandwidthSettings', []):
                            traffic_class = bandwidth_setting.get('trafficClass')
                            instance_id = bandwidth_setting.get('instanceId')
                            if traffic_class and instance_id:
                                id_bandwidth_mapping[traffic_class] = instance_id
                elif clause.get('type') == 'DSCP_CUSTOMIZATION':
                    for dscp_setting in clause.get('tcDscpSettings', []):
                        dscp = dscp_setting.get('dscp')
                        traffic_class = dscp_setting.get('trafficClass')
                        instance_id = dscp_setting.get('instanceId')
                        if dscp and traffic_class and instance_id:
                            id_dscp_mapping[traffic_class] =  instance_id

        update_required = False

        # Checking Bandwidth settings
        for key, value in final_want_bandwidth_dict.items():
            if key in have_bandwidth_settings:
                if have_bandwidth_settings[key] != value:
                    update_required = True
            else:
                update_required = True

        # Checking DSCP settings
        for key, value in final_want_dscp_dict.items():
            if key in have_dscp_settings:
                if int(have_dscp_settings[key]) != value:
                    update_required = True
            else:
                update_required = True

        if not update_required:
            self.log("No updates required. Both dictionaries match.")
        else:
            self.log("Update required.")

        instance_ids = {}
        for clause in queuing_profile['current_queuing_profile'][0]['clause']:
            if clause['type'] == 'BANDWIDTH':
                instance_ids['bandwidth'] = clause['instanceId']
            elif clause['type'] == 'DSCP_CUSTOMIZATION':
                instance_ids['dscp'] = clause['instanceId']

        interface_speed_clause = queuing_profile['current_queuing_profile'][0]['clause'][0]['interfaceSpeedBandwidthClauses'][0]
        if interface_speed_clause['interfaceSpeed'] == 'ALL':
            interface_speed_all_instance_id = interface_speed_clause['instanceId']
        
        if 'new_profile_name' in required_details:
            profile_name = required_details['new_profile_name']
        else:
            profile_name = queuing_profile['current_queuing_profile'][0].get("name")

        if 'profile_description' in required_details:
            profile_desc = required_details['profile_description']
        else:
            profile_desc = queuing_profile['current_queuing_profile'][0].get("description")
        
        # Construct the payload
        payload = [
            {
                "id": queuing_profile['current_queuing_profile'][0].get("id"),
                "name": profile_name,
                "description": profile_desc,
                "clause": [
                    {
                        "instanceId": instance_ids.get('bandwidth'),
                        "type": "BANDWIDTH",
                        "isCommonBetweenAllInterfaceSpeeds": True,
                        "interfaceSpeedBandwidthClauses": [
                            {
                                "instanceId": interface_speed_all_instance_id,
                                "interfaceSpeed": "ALL",
                                "tcBandwidthSettings": [
                                    {
                                        "instanceId": id_bandwidth_mapping[traffic_class],
                                        "trafficClass": traffic_class,
                                        "bandwidthPercentage": final_want_bandwidth_dict[traffic_class]
                                    }
                                    for traffic_class in final_want_bandwidth_dict
                                ]
                            }
                        ]
                    },
                    {
                        "instanceId": instance_ids.get('dscp'),
                        "type": "DSCP_CUSTOMIZATION",
                        "tcDscpSettings": [
                            {
                                "instanceId": id_dscp_mapping[traffic_class],
                                "trafficClass": traffic_class,
                                "dscp": final_want_dscp_dict[traffic_class]
                            }
                            for traffic_class in final_want_dscp_dict
                        ]
                    }
                ]
            }
        ]

        self.log(json.dumps(payload, indent=2))

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='update_application_policy_queuing_profile',
                op_modifies= True,
                params = {"payload": payload}
                )

            self.log(f"Received API response from 'application_policy_intent' for creation: {response}", "DEBUG")
            self.check_tasks_response_status(response, "application_policy_intent")

            if self.status not in ["failed", "exited"]:
                self.log("application policy queuing profile '{0}' updated successfully.".format(profile_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application policy queuing profile '{0}' updated successfully.".format(profile_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "update of the application policy queuing profile failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def create_queuing_profile(self):
        """
        Creates an application queuing profile in Cisco Catalyst Center.
        Description:
            This method validates the provided configuration for creating an application queuing profile. It ensures 
            mandatory fields are present and verifies the total bandwidth percentage for different interface speeds. 
            The method constructs a payload based on the provided bandwidth and DSCP settings, and invokes the 
            appropriate API to create the queuing profile. The result is logged and stored in the instance attributes.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self: The current instance of the class, updated with the result of the create operation. Updates include:
        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        new_queuing_profile_details = self.config.get("application_queuing_details", [])[0]
        self.log(f"Queuing Profile Details: {new_queuing_profile_details}")

        # Check for mandatory fields
        mandatory_fields = ["profile_name"]

        for field in mandatory_fields:
            if not new_queuing_profile_details.get(field):
                self.status = "failed"
                self.msg = (
                    "The following parameter(s): {0} could not be found  and are mandatory to create application queuing profile."
                ).format(field)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()

        if new_queuing_profile_details['bandwidth_settings']['is_common_between_all_interface_speeds'] == False:
            if 'bandwidth_settings' in new_queuing_profile_details:
                for interface in new_queuing_profile_details['bandwidth_settings']['interface_speed_settings']:
                    total_percentage = sum(int(value) for value in interface['bandwidth_percentages'].values())

                    if total_percentage != 100:
                        msg = (f"Validation ERROR at interface speed: {interface['interface_speed']} "
                            f"(Total: {total_percentage}%) Should be total 100%")
                        self.status = "failed"
                        self.msg = msg
                        self.log(msg, "ERROR")
                        self.result['response'] = self.msg
                        self.check_return_status()

        # Construct payload
        if new_queuing_profile_details.get('bandwidth_settings', {}).get('is_common_between_all_interface_speeds') == True or new_queuing_profile_details.get('type') == ['dscp']:
          param = {
              "name": new_queuing_profile_details.get('profile_name', ''),
              "description": new_queuing_profile_details.get('policy_description', ''),
              "clause": []
          }

          if new_queuing_profile_details.get('bandwidth_settings'):
              self.log("As we are passing common traffic class bandwidth percentage for all the interface speeds")
              bandwidth_clause = {
                  "type": "BANDWIDTH",
                  "isCommonBetweenAllInterfaceSpeeds": new_queuing_profile_details['bandwidth_settings'].get(
                      'is_common_between_all_interface_speeds', False
                  ),
                  "interfaceSpeedBandwidthClauses": [
                      {
                          "interfaceSpeed": new_queuing_profile_details['bandwidth_settings'].get('interface_speed', ''),
                          "tcBandwidthSettings": [
                              {
                                  "trafficClass": key.upper(),
                                  "bandwidthPercentage": int(value)
                              }
                              for key, value in new_queuing_profile_details['bandwidth_settings']['bandwidth_percentages'].items()
                          ]
                      }
                  ]
              }
              param['clause'].append(bandwidth_clause)

          if new_queuing_profile_details.get('dscp_settings'):
              dscp_clause = {
                  "type": "DSCP_CUSTOMIZATION",
                  "tcDscpSettings": [
                      {
                          "trafficClass": key.upper(),
                          "dscp": value
                      }
                      for key, value in new_queuing_profile_details['dscp_settings'].items()
                  ]
              }
              param['clause'].append(dscp_clause)

        elif new_queuing_profile_details['bandwidth_settings']['is_common_between_all_interface_speeds'] == False:

            self.log("As we are passing different traffic class bandwidth percentage for six different interface speeds")
            param = {
                "name": new_queuing_profile_details['profile_name'],
                "description": new_queuing_profile_details['policy_description'],
                "clause": [
                    {
                        "isCommonBetweenAllInterfaceSpeeds": new_queuing_profile_details['bandwidth_settings']['is_common_between_all_interface_speeds'],
                        "interfaceSpeedBandwidthClauses": []
                    }
                ]
            }

            for interface in new_queuing_profile_details['bandwidth_settings']['interface_speed_settings']:
                # Split the comma-separated interface speeds
                interface_speeds = interface['interface_speed'].split(',')
                for speed in interface_speeds:
                    # Create the interface speed clause
                    interface_speed_clause = {
                        "interfaceSpeed": speed.strip(),
                        "tcBandwidthSettings": [
                            {
                                "trafficClass": key.upper(),
                                "bandwidthPercentage": int(value)
                            }
                            for key, value in interface['bandwidth_percentages'].items()
                        ]
                    }
                    # Append the clause to the main structure
                    param["clause"][0]["interfaceSpeedBandwidthClauses"].append(interface_speed_clause)

            # Add dscp settings if available
            if 'dscp_settings' in new_queuing_profile_details:
                dscp_clause = {
                    "type": "DSCP_CUSTOMIZATION",
                    "tcDscpSettings": [
                        {
                            "trafficClass": key.upper(),
                            "dscp": value
                        }
                        for key, value in new_queuing_profile_details['dscp_settings'].items()
                    ]
                }
                param['clause'].append(dscp_clause)

        self.log(f"Payload for Queuing Profile: {json.dumps(param, indent=4)}")

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='create_application_policy_queuing_profile',
                op_modifies= True,
                params = {"payload": [param]}
            )

            self.log(f"Received API response from 'create_application_policy_queuing_profile': {response}", "DEBUG")
            self.check_tasks_response_status(response, "create_application_policy_queuing_profile")

            if self.status not in ["failed", "exited"]:
                self.log("application queuing profile created successfully.", "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application queuing profile created successfully.").format()
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = (
                    "failed to create application queing profile reason - {0}").format(fail_reason)
                self.log(self.msg, "ERROR")
                self.result['response'] = self.msg
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def get_diff_deleted(self,config):
        """
        Manages the deletion of an application set based on the provided configuration.
        Description:
            This method checks the provided `config` for `application_set_details`. If the details are found, it triggers 
            the `delete_application_set` method to delete the application set and subsequently checks the return status 
            of the operation.
        Parameters:
            config (dict): A dictionary containing the configuration details, including `application_set_details`.
        Returns:
            None: The method performs the operation but does not return any value.
        Raises:
            None: Any errors or unexpected behaviors are handled internally by the called methods.
        """

        self.config = config

        if config.get("application_set_details"):
            self.delete_application_set().check_return_status()

        if config.get("application_queuing_details"):
            self.delete_application_queuing_profile().check_return_status()

        if config.get("application_details"):
            self.delete_application().check_return_status()

        if config.get("application_policy_details"):
            self.delete_application_policy().check_return_status()

    def delete_application_policy(self):
        """
        Delete an existing application policy in Cisco DNA Center.

        Parameters:
            self (object): An instance of the class for interacting with Cisco DNA Center.

        Returns:
            self: The updated instance with 'status', 'msg', and 'result' attributes.

        Description:
            This method deletes an application policy from Cisco DNA Center by first checking if the policy exists. 
            If the policy is not found, it logs a message and returns. If the policy exists, it retrieves the 
            policy ID and sends a delete request to Cisco DNA Center via the API. The response is processed, 
            and the method logs success or failure. If an error occurs, it is caught and handled appropriately.
        """

        application_policy_details = self.config.get("application_policy_details")
        self.log(f"Queuing Profile Details: {application_policy_details}")
        application_policy_name = application_policy_details.get("application_policy_name")
        application_policy_details = self.have


        if application_policy_details.get("application_policy_exists") == False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "application policy '{0}' does not present in the cisco catalyst center or its been already deleted".format(application_policy_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        get_ids = self.have
        ids_list = []

        if "current_application_policy" in get_ids:
            for policy in get_ids["current_application_policy"]:
                if "id" in policy:
                    ids_list.append(policy["id"])

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='application_policy_intent',
                op_modifies= True,
                params= {'deleteList': ids_list,}
                )

            self.log(f"Received API response from 'application_policy_intent' for deletion: {response}", "DEBUG")
            self.check_tasks_response_status(response, "application_policy_intent")

            if self.status not in ["failed", "exited"]:
                self.log("application policy '{0}' deleted successfully.".format(application_policy_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application policy '{0}' deleted successfully.".format(application_policy_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "deletion of the application policy failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "{0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def delete_application_queuing_profile(self):
        """
        Deletes an existing application set in Cisco Catalyst Center.
        Description:
            This method checks if the specified application set exists in Cisco Catalyst Center. If the application set does 
            not exist or has already been deleted, it logs the status and exits without performing any operations. If the 
            application set exists, the method retrieves its ID and triggers the appropriate API call to delete it. The 
            method monitors the task's response status and logs the outcome.
        Parameters:
            None: The method uses the `config` attribute to retrieve application set details, such as `application_set_name`.
        Returns:
            self: The current instance of the class, updated with the result of the delete operation.
        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        application_queuing_profile_details = self.config.get("application_queuing_details", [])[0]
        self.log(f"Queuing Profile Details: {application_queuing_profile_details}")
        application_queuing_profile_name = application_queuing_profile_details.get("profile_name")
        application_queuing_profile_details = self.have
        self.log(application_queuing_profile_details)

        if application_queuing_profile_details.get("queuing_profile_exists") == False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "application queuing profile '{0}' does not present in the cisco catalyst center or its been already deleted".format(application_queuing_profile_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        queuing_profile_id = application_queuing_profile_details.get('current_queuing_profile', [])[0].get('id', None)
        self.log(queuing_profile_id)

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='delete_application_policy_queuing_profile',
                op_modifies= True,
                params= {'id': queuing_profile_id,}
                )

            self.log(f"Received API response from 'create_application_set': {response}", "DEBUG")
            self.check_tasks_response_status(response, "create_application_policy_queuing_profile")

            if self.status not in ["failed", "exited"]:
                self.log("application policy queuing profile '{0}' deleted successfully.".format(application_queuing_profile_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application policy queuing profile '{0}' deleted successfully.".format(application_queuing_profile_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "deletion of the application policy queuing profile failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def delete_application_set(self):
        """
        Deletes an existing application set in Cisco Catalyst Center.
        Description:
            This method checks if the specified application set exists in Cisco Catalyst Center. If the application set does 
            not exist or has already been deleted, it logs the status and exits without performing any operations. If the 
            application set exists, the method retrieves its ID and triggers the appropriate API call to delete it. The 
            method monitors the task's response status and logs the outcome.
        Parameters:
            None: The method uses the `config` attribute to retrieve application set details, such as `application_set_name`.
        Returns:
            self: The current instance of the class, updated with the result of the delete operation.
        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        application_set_detail = self.config.get("application_set_details", [])[0]
        self.log(f"Queuing Profile Details: {application_set_details}")
        application_set_name = application_set_details.get("application_set_name")
        application_set_details = self.have

        if application_set_details.get("application_set_exists") == False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "application set '{0}' does not present in the cisco catalyst center or its been already deleted".format(application_set_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        application_set_id = application_set_details['current_application_set'][0]['id'] if application_set_details['current_application_set'] else None
        self.log(application_set_id)

        try:
            response = self.dnac._exec(
                family="application_policy",
                function='delete_application_set',
                op_modifies= True,
                params= {'id': application_set_id, }
                )

            self.log(f"Received API response from 'create_application_set': {response}", "DEBUG")
            self.check_tasks_response_status(response, "create_application_policy_queuing_profile")

            if self.status not in ["failed", "exited"]:
                self.log("application set '{0}' deleted successfully.".format(application_set_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application set '{0}' deleted successfully.".format(application_set_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "deletion of the application set failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "".format()
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def delete_application(self):
        """
        Deletes an existing application in Cisco Catalyst Center.
        Description:
            This method checks if the specified application exists in Cisco Catalyst Center. If the application 
            does not exist or has already been deleted, it logs the status and exits without performing any operations. 
            If the application exists, the method retrieves its ID and triggers the appropriate API call to delete it. 
            The method monitors the task's response status and logs the outcome.
        Parameters:
            None: The method uses the `config` attribute to retrieve application details, such as `application_name`.
        Returns:
            self: The current instance of the class, updated with the result of the delete operation. Updates include:
        Raises:
            None: Any errors or unexpected behaviors are handled within the method and logged appropriately.
        """

        application_details = self.config.get("application_details", [])
        self.log(f"application Details: {application_details}")
        application_name = application_details.get("application_name")
        application_deatils = self.have

        if application_deatils.get("application_exists") == False:
            self.status = "success"
            self.result['changed'] = False
            self.msg = "application set '{0}' does not present in the cisco catalyst center or its been already deleted".format(application_name)
            self.result['msg'] = self.msg
            self.result['response'] = self.msg
            self.log(self.msg, "INFO")
            return self

        application_id = application_deatils['current_application'][0]['id'] if application_deatils['current_application'] else None
        self.log(application_id)

        try:
            self.log("outter")
            response = self.dnac._exec(
                family="application_policy",
                function='delete_application_set2',
                op_modifies= True,
                params = {'id': application_id,}
                )
            self.log("inner")
            self.log(f"Received API response from 'delete_application': {response}", "DEBUG")
            self.check_tasks_response_status(response, "delete_application")

            if self.status not in ["failed", "exited"]:
                self.log("application '{0}' deleted successfully.".format(application_name), "INFO")
                self.status = "success"
                self.result['changed'] = True
                self.msg = ("application '{0}' deleted successfully.".format(application_name))
                self.result['response'] = self.msg
                return self

            if self.status == "failed":
                fail_reason = self.msg
                self.status = "failed"
                self.msg = "deletion of the application failed due to - {0}".format(fail_reason)
                self.result['response'] = self.msg
                self.log(self.msg, "ERROR")
                self.check_return_status()

        except Exception as e:
            self.status = "failed"
            self.msg = "error - {0}".format(e)
            self.result['response'] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()


def main():
    """ main entry point for module execution
    """

    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin', 'aliases': ['user']},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'config_verify': {'type': 'bool', "default": False},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'merged', 'choices': ['merged','deleted']}
                    }

    module = AnsibleModule(argument_spec=element_spec,
                            supports_check_mode=False)
    ccc_application = ApplicationPolicy(module)
    state = ccc_application.params.get("state")

    if state not in ccc_application.supported_states:
        ccc_application.status = "invalid"
        ccc_application.msg = "State {0} is invalid".format(state)
        ccc_application.check_return_status()

    ccc_application.validate_input().check_return_status()
    config_verify = ccc_application.params.get("config_verify")

    for config in ccc_application.validated_config:
        ccc_application.reset_values()
        ccc_application.get_want(config).check_return_status()
        ccc_application.get_have().check_return_status()
        ccc_application.get_diff_state_apply[state](config)#.check_return_status()
        # if config_verify:
        #     ccc_application.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_application.result)


if __name__ == '__main__':
    main()
