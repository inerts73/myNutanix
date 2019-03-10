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
    URL = 'https://10.40.184.147:9440/api/nutanix/v3/recovery_points/13d2024f-6ba8-4d55-9738-71a12e7d53e7/restore'
    METHOD = 'post'
    DATA = {
      "vm_list": [
        {
          "vm_recovery_point_reference": {
            "kind": "vm_recovery_point",
            "uuid": "4190cf6c-3808-4818-9c7d-03055bbe3135"
          },
          "vm_spec": {
            "name": "R_DEBUG_ADAM_VM",
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
                  "mac_address": "D3:AC:11:32:A3:53", #Invalid mac address
                  #"mac_address": "50:6B:8D:d5:7e:8d", #Valid mac address
                  "subnet_reference": {
                    "kind": "subnet",
                    "name": "vlan_override_777",
                    "uuid": "2d4045ae-660b-4925-b5fc-4219e622c99c"
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

    # URL = 'https://10.40.184.147:9440/api/nutanix/v3/recovery_points/13d2024f-6ba8-4d55-9738-71a12e7d53e7/restore'
    # METHOD = 'post'
    # DATA = {
    #   "vm_list": [
    #     {
    #       "vm_recovery_point_reference": {
    #         "kind": "vm_recovery_point",
    #         "uuid": "4190cf6c-3808-4818-9c7d-03055bbe3135"
    #       },
    #       "vm_spec": {
    #         "name": "R_DEBUG_ADAM_VM"
    #       },
    #       "metadata": {
    #         "categories_mapping": {
    #           "MartialArt": ["Judo"] #Category not existing on PC
    #           #"AccessType": ["Internet"] #Category existing on PC
    #         }
    #       }
    #     }
    #   ]
    # }
    # DATA = json.dumps(DATA)

    res = send_req(url=URL, method=METHOD, data=DATA)
    print
    print 'content => ', json.dumps(json.loads(res.content), indent=2)
    print 'status => ', res
    with open("TEMP_http_post_try.josn", "w") as fp:
        json.dump(json.loads(res.content), fp, indent=2)
    print "content saved in => TEMP_http_post_try.json"
