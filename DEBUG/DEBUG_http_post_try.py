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
  URL = 'https://10.40.216.115:9440/api/nutanix/v3/availability_zones/list'
  METHOD = 'post'
  DATA = {"kind": "availability_zone", "length": 500, "offset": 0}
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def replicate_from_srouce_to_remote():
  URL = 'https://10.40.216.115:9440/api/nutanix/v3/recovery_points/01cc10a9-d6ec-42e4-826b-7d4f6fca79fa/replicate'
  METHOD = 'post'
  DATA = {
    "source_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "Local AZ",
      "uuid": "c82446a8-8d05-4530-8b2f-075b48a5658c"
    },
    "target_cluster_reference": {
      "kind": "cluster",
      "name": "auto_AdamHsu_Cluster_ThreeA",
      "uuid": "00058503-7aa2-5965-0000-000000011600"
    },
    "target_availability_zone_reference": {
      "kind": "availability_zone",
      "name": "PC_10.40.184.38",
      "uuid": "f69161f0-3f4f-4c7a-a9f5-156b20aa8453"
    }
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def restore_on_pc_full():
  URL = 'https://10.40.184.38:9440/api/nutanix/v3/recovery_points/3951e2bc-ce14-45e1-9595-5e7ea97db71b/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "c908e845-ecd5-4e13-a17f-9d06c2da81a9"
        },
        "vm_spec": {
          "name": "R_DEBUG_RESTORE_01",
          "resources": {
            "nic_list": [
              {
                "nic_type": "NORMAL_NIC",
                "uuid": "12345678-9abc-def0-1234-56789abcdef0",
                "ip_endpoint_list": [
                  {
                    "type": "ASSIGNED"
                  }
                ],
                "vlan_mode": "ACCESS",
                "mac_address": "50:6B:8D:d5:7e:8d",
                "subnet_reference": {
                  "kind": "subnet",
                  "name": "vlan_override_777",
                  "uuid": "f844308a-7c46-459c-8494-8008dca8a3a1"
                },
                "is_connected": True,
                "trunked_vlan_list": []
              }
            ]
          }
        },
        "metadata": {
          "categories_mapping": {
            "Environment": ["Dev"]  # Category existing on PC
          }
        }
      }
    ]
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def restore_on_pc_mini():
  URL = 'https://10.40.218.135:9440/api/nutanix/v3/recovery_points/c4ba67fc-64c8-41a0-8959-bc3952ae557f/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "4e485287-d58d-47f7-b7a2-9ca808596592"
        },
        "vm_spec": {
          "name": "RESTORE_2_DISKS"
        }
      }
    ]
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def vm_info():
    URL = 'https://10.40.184.38:9440/api/nutanix/v3/vms/d144125a-68c3-4249-8226-5f0d2fa84bd2'
    METHOD = 'get'
    DATA = {}
    DATA = json.dumps(DATA)

    return URL, METHOD, DATA

if __name__ == '__main__':
  #output_to_json_file(*az_list())
  #output_to_json_file(*replicate_from_srouce_to_remote())
  #output_to_json_file(*restore_on_pc_full())
  output_to_json_file(*restore_on_pc_mini())
  #output_to_json_file(*vm_info())


