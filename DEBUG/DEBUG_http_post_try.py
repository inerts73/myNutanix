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
  URL = 'https://10.40.217.29:9440/api/nutanix/v3/recovery_points/b93bd453-4207-42fa-b682-f98ea4ee4fdc/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "a15e8fd5-4d00-4ef9-aa87-4a870cb05784"
        },
        "vm_spec": {
          "name": "RESTORE_01",
          "resources": {
            "gpu_list": [
              {
                "vendor": "NVIDIA",
                "mode": "VIRTUAL",
                "device_id": 12
              }
            ],
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
                "mac_address": "50:6b:8d:be:a9:68",
                "subnet_reference": {
                  "kind": "subnet",
                  "name": "vlan_override_777",
                  "uuid": "d73cc07f-c937-4546-8683-957d75bf044b"
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
  URL = 'https://10.40.184.5:9440/api/nutanix/v3/recovery_points/324f613b-fb4f-402e-a6f6-b3a0551964ae/restore'
  METHOD = 'post'
  DATA = {
    "vm_list": [
      {
        "vm_recovery_point_reference": {
          "kind": "vm_recovery_point",
          "uuid": "aac92ebd-2d68-4ef6-b18e-ca4a37fcaf71"
        },
        "vm_spec": {
          "name": "RESTORE_02"
        }
      }
    ]
  }
  DATA = json.dumps(DATA)

  return URL, METHOD, DATA

def vm_info():
    URL = 'https://10.40.217.29:9440/api/nutanix/v3/vms/2fd4a9e1-044f-511d-b4fd-1646bcd8e228'
    METHOD = 'get'
    DATA = {}
    DATA = json.dumps(DATA)

    return URL, METHOD, DATA

if __name__ == '__main__':
  #output_to_json_file(*az_list())
  #output_to_json_file(*replicate_from_srouce_to_remote())
  #output_to_json_file(*restore_on_pc_full())
  #output_to_json_file(*restore_on_pc_mini())
  output_to_json_file(*vm_info())







