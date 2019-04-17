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

def replicate_from_srouce_to_remote():
  URL = 'https://10.40.217.14:9440/api/nutanix/v3/recovery_points/1ee94f35-c628-4b65-b6a8-6d6a414ce8ac/replicate'
  METHOD = 'post'
  DATA = {
    "source_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "Local AZ",
      "uuid": "d4e8a1c5-99e9-468f-9113-6169fa24e91e"
    },
    "target_cluster_reference": {
      "kind": "cluster",
      "name": "auto_AdamHsu_Cluster_OneAD",
      "uuid": "192c78ee-2ec2-402b-b51b-789eb34fbe80"
    },
    "target_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "PC_10.40.216.245",
      "uuid": "e9e5359f-56a8-4ad2-a3d4-e90945fe88b8"
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
  URL = 'https://10.40.184.59:9440/api/nutanix/v3/recovery_points/3b510cf5-6ce7-446a-a873-6d1d41bd2837/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "e04c81b7-1c82-4962-b690-8e10e2932bca"
        },
        "vm_spec": {
          "name": "RESTORE_1AF_MINI"
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
  #output_to_json_file(*replicate_from_srouce_to_remote())
  #output_to_json_file(*restore_on_pc_full())
  #output_to_json_file(*restore_on_pc_mini())
  output_to_json_file(*task_info())
  #output_to_json_file(*vm_info())







