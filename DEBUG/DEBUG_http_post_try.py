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
  URL = 'https://10.40.217.252:9440/api/nutanix/v3/recovery_points/61e431c6-9e94-438d-b591-ac518d2137c2/replicate'
  METHOD = 'post'
  DATA = {
    "source_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "Local AZ",
      "uuid": "e85f4d6b-9776-4fd3-9c65-ba654d73d356"
    },
    "target_cluster_reference": {
      "kind": "cluster",
      "name": "auto_AdamHsu_Cluster_OneAM",
      "uuid": "0e1ed090-72f0-4174-95e3-62ce9d674c2c"
    },
    "target_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "PC_10.40.216.172",
      "uuid": "e3c1ebd9-416a-421d-a1b3-372c00b93d47"
    }
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def restore_on_pc_full_source():
  URL = 'https://10.40.184.8:9440/api/nutanix/v3/recovery_points/2f5ec6d7-636d-4fc2-936e-9dee0eb21862/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "801624fc-dedd-4923-996e-336e3a5ac09a"
        },
        "vm_spec": {
          "name": "RESTORE_1AP_FULL_SOURCE",
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
                  "uuid": "604c35e0-7860-46c1-822d-2fa7e0e73dba"
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
  URL = 'https://10.40.184.8:9440/api/nutanix/v3/recovery_points/2f5ec6d7-636d-4fc2-936e-9dee0eb21862/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "801624fc-dedd-4923-996e-336e3a5ac09a"
        },
        "vm_spec": {
          "name": "RESTORE_1AP_MINI_SOURCE",
          "resources": {
            "nic_list": [
              {
                "nic_type": "NORMAL_NIC",
                "subnet_reference": {
                  "kind": "subnet",
                  "uuid": "604c35e0-7860-46c1-822d-2fa7e0e73dba"
                }
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
  URL = 'https://10.40.218.70:9440/api/nutanix/v3/recovery_points/e8d81ed5-dabc-41be-bf1b-41b523783253/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "b970e40e-1627-491a-a0f0-e3eaff664aa9"
        },
        "vm_spec": {
          "name": "RESTORE_1AU_MINI_REMOTE",
          "resources": {
            "nic_list": [
              {
                "nic_type": "NORMAL_NIC",
                "subnet_reference": {
                  "kind": "subnet",
                  "uuid": "9b8551d7-0ea4-485f-86f5-dc7dfdfb2abe"
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

def vm_info():
  URL = 'https://10.40.184.59:9440/api/nutanix/v3/vms/79333bf6-1700-51f7-a8f3-6972695b91fc'
  METHOD = 'get'
  DATA = {}
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

if __name__ == '__main__':
  #output_to_json_file(*az_list())
  #output_to_json_file(*idempotence_identifiers_create())
  #output_to_json_file(*replicate_from_srouce_to_remote())
  #output_to_json_file(*restore_on_pc_full_source())
  #output_to_json_file(*restore_on_pc_full_remote())
  #output_to_json_file(*restore_on_pc_mini_source())
  output_to_json_file(*restore_on_pc_mini_remote())
  #output_to_json_file(*task_info())
  #output_to_json_file(*vm_info())







