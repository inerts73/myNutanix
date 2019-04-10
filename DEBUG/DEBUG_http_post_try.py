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
  URL = 'https://10.40.217.150:9440/api/nutanix/v3/availability_zones/list'
  METHOD = 'post'
  DATA = {"kind": "availability_zone", "length": 500, "offset": 0}
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def replicate_from_srouce_to_remote():
  URL = 'https://10.40.184.185:9440/api/nutanix/v3/recovery_points/2136f407-3e8e-4734-aea5-f697471faea5/replicate'
  METHOD = 'post'
  DATA = {
    "source_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "Local AZ",
      "uuid": "4eafa1b8-f3e8-4684-85bc-4b24a8acec73"
    },
    "target_cluster_reference": {
      "kind": "cluster",
      "name": "auto_AdamHsu_Cluster_OneZ",
      "uuid": "db6a708a-0f52-4cd1-9179-b0e7116804dd"
    },
    "target_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "PC_10.40.184.183",
      "uuid": "16637130-cd49-40c7-ac07-72a4300f8445"
    }
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def restore_on_pc_full():
  URL = 'https://10.40.216.227:9440/api/nutanix/v3/recovery_points/51e56c0f-ee3e-4902-b557-95116b669851/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "90916111-08e9-4fc2-ada8-2ff9845a85dc"
        },
        "vm_spec": {
          "name": "RESTORE_1W_FULL",
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
                  "uuid": "58318e27-40cb-453e-8a77-beac024b361f"
                },
                "is_connected": True,
                "mac_address": "50:6b:8d:79:c1:f9"
              },
              {
                "ip_endpoint_list": [
                  {
                    "type": "ASSIGNED"
                  }
                ],
                "nic_type": "DIRECT_NIC",
                "subnet_reference": {
                  "kind": "subnet",
                  "uuid": "58318e27-40cb-453e-8a77-beac024b361f"
                },
                "is_connected": True,
                "mac_address": "50:6b:8d:4e:11:95"
              }
            ]
          }
        }
        # "metadata": {
        #   "categories_mapping": {
        #     "Environment": [
        #       "Staging",
        #       "Testing"
        #     ],
        #     "AccessType": [
        #       "Internet"
        #     ]
        #   }
        # }
      }
    ]
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def restore_on_pc_mini():
  URL = 'https://10.40.184.185:9440/api/nutanix/v3/recovery_points/2136f407-3e8e-4734-aea5-f697471faea5/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "edce7d6d-c2b5-4701-93b6-8ca0b5712acf"
        },
        "vm_spec": {
          "name": "RESTORE_1AA_MINI"
        }
      }
    ]
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def vm_info():
    URL = 'https://10.40.217.29:9440/api/nutanix/v3/vms/657b7410-25b0-5ab3-a2df-383ad009ac1c'
    METHOD = 'get'
    DATA = {}
    DATA = json.dumps(DATA)

    return URL, METHOD, DATA

if __name__ == '__main__':
  #output_to_json_file(*az_list())
  output_to_json_file(*replicate_from_srouce_to_remote())
  #output_to_json_file(*restore_on_pc_full())
  #output_to_json_file(*restore_on_pc_mini())
  #output_to_json_file(*vm_info())







