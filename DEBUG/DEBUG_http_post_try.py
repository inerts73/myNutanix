import json
from requests import Session

def output_to_json_file(URL, METHOD, DATA):
  res = send_req(url=URL, method=METHOD, data=DATA)
  print
  print 'content => ', json.dumps(json.loads(res.content), indent=2)
  print 'status => ', res
  with open("TEMP_http_post_try.josn", "w") as fp:
    json.dump(json.loads(res.content), fp, indent=2)
  print "content saved in => TEMP_http_post_try.json"

def send_req(url, method, params={}, data={},
                 header={'content-type': 'application/json;charset=UTF-8',
                         'Accept': 'application/json,'
                         'text/javascript, */*; q=0.01'},
                 auth=('admin', 'Nutanix.123'), timeout=30, verify=False):

    return Session().request(url=url, method=method, params=params,
                             data=data, headers=header, auth=auth,
                             timeout=timeout, verify=verify)

##################################################

def az_list():
  URL = 'https://10.40.217.14:9440/api/nutanix/v3/availability_zones/list'
  METHOD = 'post'
  DATA = {"kind": "availability_zone", "length": 500, "offset": 0}
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def idempotence_identifiers_create():
  URL = 'https://10.40.216.172:9440/api/nutanix/v3/idempotence_identifiers'
  METHOD = 'post'
  DATA = {
    "client_identifier": "string",
    "count": 3,
    "valid_duration_in_minutes": 527040
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def replicate_from_srouce_to_remote():
  URL = 'https://10.40.184.24:9440/api/nutanix/v3/recovery_points/03fe8f6c-caf4-47d0-98bf-fc9795fb999d/replicate'
  METHOD = 'post'
  DATA = {
    "source_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "Local AZ",
      "uuid": "dfe3016e-2e59-458c-911d-30f50bc5a651"
    },
    "target_cluster_reference": {
      "kind": "cluster",
      "name": "auto_AdamHsu_Cluster_OneBA",
      "uuid": "00058845-343a-c751-0000-00000000496e"
    },
    "target_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "PC_10.40.184.19",
      "uuid": "e9d8e966-2d04-410d-8f4d-76397322c137"
    }
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def restore_on_pc_full_source():
  URL = 'https://10.40.184.215:9440/api/nutanix/v3/recovery_points/d8da6d95-4ffd-4aab-a7db-795c65fb82bb/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "da3bb289-1792-4b30-b976-53409b54784d"
        },
        "vm_spec": {
          "name": "RESTORE_3X_G_0_0",
          "resources": {
            "nic_list": [
              {
                "ip_endpoint_list": [
                  {
                    "type": "ASSIGNED"
                  }
                ],
                "nic_type": "DIRECT_NIC",
                "subnet_reference": {
                  "kind": "subnet",
                  "uuid": "e5fa694f-b1a1-4a9a-ba92-f63f6f8f9b36"
                },
                "is_connected": True,
                "mac_address": "50:6b:8d:be:a9:68"
              }
            ],
            "gpu_list": [
              {
                "device_id": 12,
                "mode": "VIRTUAL",
                "vendor": "INTEL"
              }
            ]
          }
        }
      }
    ]
  }
  DATA = json.dumps(DATA)
  return URL, METHOD, DATA

def restore_on_pc_full_remote():
  URL = 'https://10.40.184.107:9440/api/nutanix/v3/recovery_points/562ba05e-5b66-4e00-a2ce-adf359e12b79/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "f8ee1887-7c3b-492c-a699-c38089735af4"
        },
        "vm_spec": {
          "name": "RESTORE_1AO_FULL",
          "resources": {
            "nic_list": [
              {
                "ip_endpoint_list": [
                  {
                    "type": "ASSIGNED"
                  }
                ],
                "nic_type": "DIRECT_NIC",
                "subnet_reference": {
                  "kind": "subnet",
                  "uuid": "2778b2e6-8264-4b6f-b6ac-a4f35b362658"
                },
                "is_connected": True,
                "mac_address": "50:6b:8d:79:c1:f9"
              }
            ]
          }
        }
      }
    ]
  }
  DATA = json.dumps(DATA)
  return URL, METHOD, DATA

def restore_on_pc_mini_source():
  URL = 'https://10.40.184.215:9440/api/nutanix/v3/recovery_points/601d7210-97a1-4d2c-9b13-632f7e0e75a7/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "485a29ab-3402-4ab2-b344-a88d307e9f34"
        },
        "vm_spec": {
          "name": "RESTORE_G_3X",
          "resources": {
            "nic_list": [
              {
                "nic_type": "NORMAL_NIC",
                "subnet_reference": {
                  "kind": "subnet",
                  "uuid": "f41f2fe1-a8db-44b7-b31b-461fc0fc6941"
                }
              }
            ],
            "gpu_list": [
              {
                "device_id": 33,
                "mode": "VIRTUAL",
                "vendor": "INTEL"
              }
            ]
          }
        },
        "metadata": {
          "categories_mapping": {
            "Environment": [
              "Staging",
              "Testing"
            ],
            "AppTier": [
              "Default"
            ]
          }
        }
      }
    ]
  }
  DATA = json.dumps(DATA)
  return URL, METHOD, DATA

def restore_on_pc_mini_remote():
  URL = 'https://10.40.216.100:9440/api/nutanix/v3/recovery_points/67be39e3-79e2-4a0c-80c8-777568302bda/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "0fd98786-ef23-4401-9b22-7e06c890e1a9"
        },
        "vm_spec": {
          "name": "RESTORE_1BC_NIC",
          "resources": {
            "nic_list": [
              {
                "nic_type": "NORMAL_NIC",
                "subnet_reference": {
                  "kind": "subnet",
                  "uuid": "dd91fce9-c0d0-4ecb-8774-dcb58526a937"
                }
              }
            ]
          }
        }
      }
    ]
  }
  DATA = json.dumps(DATA)
  return URL, METHOD, DATA

def task_info():
  URL = 'https://10.40.184.59:9440/api/nutanix/v3/tasks/273d7f9e-a94f-42f7-abc7-247d86f29a2b'
  METHOD = 'get'
  DATA = {}
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def vm_info_pc():
  URL = 'https://10.40.184.215:9440/api/nutanix/v3/vms/b0c5d2a0-299e-495d-86ef-780c6add9ec2'
  METHOD = 'get'
  DATA = {}
  DATA = json.dumps(DATA)
  return URL, METHOD, DATA

def vm_list_pc():
  URL = 'https://10.40.184.215:9440/api/nutanix/v3/vms/list'
  METHOD = 'post'
  DATA = {}
  DATA = json.dumps(DATA)
  return URL, METHOD, DATA

def vm_list_pe():
  URL = 'https://10.45.146.172:9440/PrismGateway/services/rest/v2.0/vms/'
  METHOD = 'get'
  DATA = {}
  return URL, METHOD, DATA

if __name__ == '__main__':
  #output_to_json_file(*az_list())
  #output_to_json_file(*idempotence_identifiers_create())
  #output_to_json_file(*replicate_from_srouce_to_remote())
  #output_to_json_file(*restore_on_pc_full_source())
  #output_to_json_file(*restore_on_pc_full_remote())
  #output_to_json_file(*restore_on_pc_mini_source())
  #output_to_json_file(*restore_on_pc_mini_remote())
  #output_to_json_file(*task_info())
  #output_to_json_file(*vm_info_pc())
  #output_to_json_file(*vm_list_pc())
  output_to_json_file(*vm_list_pe())







