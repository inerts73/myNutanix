import json
from requests import Session

def send_req(url, method, params={}, data={},
                 header={'content-type': 'application/json;charset=UTF-8',
                         'Accept': 'application/json,'
                         'text/javascript, */*; q=0.01'},
                 auth=('admin', 'Nutanix.123'), timeout=30, verify=False):

    return Session().request(url=url, method=method, params=params,
                             data=data, headers=header, auth=auth,
                             timeout=timeout, verify=verify)


if __name__ == '__main__':
    # auto_AdamHsu_PC_OneI: 10.40.217.48 / auto_AdamHsu_Cluster_OneI: 10.45.146.136
    # URL = 'https://10.40.217.48:9440/api/nutanix/v3/recovery_points/81fb6d12-7b66-4e1c-b935-f0467f3b4f68/restore'
    # vm_rp_uuid = "802976f1-8cf2-4ab2-8e31-43131fab23dd"
    # name = "MAC_RESTORED_68"
    # ip = "10.15.19.10"
    # mac = "50:6b:8d:be:a9:68"

    URL = 'https://10.40.217.48:9440/api/nutanix/v3/recovery_points/aac700f3-c39a-43ad-82d2-a6b553619329/restore'
    vm_rp_uuid = "ec4e5262-973f-42e2-894f-eeb1fc38f53f"
    name = "MAC_RESTORED_dc"
    ip = "10.15.19.11"
    mac = "50:6b:8d:a3:40:dc"

    METHOD = 'post'
    DATA = {
      "vm_list": [
        {
          "vm_recovery_point_reference": {
            "kind": "vm_recovery_point",
            "uuid": vm_rp_uuid
          },
          "vm_spec": {
            "name": name,
            "resources": {
              "nic_list": [
                {
                  "nic_type": "NORMAL_NIC",
#                  "uuid": "9be11f7a-de3d-4526-9f97-5dc95a3f26ef",
                  "ip_endpoint_list": [
                    {
                      "ip": ip,
                      "type": "ASSIGNED"
                    }
                  ],
                  "vlan_mode": "ACCESS",
                  "mac_address": mac,
                  "subnet_reference": {
                    "kind": "subnet",
                    "name": "vlan_override_777",
                    "uuid": "38e2ece1-7442-49b2-b05a-fc858bbf6dee"
                  },
                  "is_connected": True,
                  "trunked_vlan_list": []
                }
              ]
            }
          }
        }
      ]
    }
    DATA = json.dumps(DATA)

    # Get a vm on PC
    # MAC_RESTORED_68
    # URL = 'https://10.40.217.48:9440/api/nutanix/v3/vms/40e63fa3-d03a-5b97-8ee0-abc494c6fb08'
    # MAC_RESTORED_dc
    # URL = 'https://10.40.217.48:9440/api/nutanix/v3/vms/84c51bb3-ecdc-52fd-8d90-323ee174426f'

    # METHOD = 'get'
    # DATA = {}
    # DATA = json.dumps(DATA)

    print
    print 'content => ', json.dumps(json.loads(res.content), indent=2)
    print 'status => ', res
    with open("TEMP_http_post_try.josn", "w") as fp:
        json.dump(json.loads(res.content), fp, indent=2)
    print "content saved in => TEMP_http_post_try.json"
