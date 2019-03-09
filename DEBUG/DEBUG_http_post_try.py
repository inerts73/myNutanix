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
    ########## categories
    # List all categories on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/categories/list'
    # METHOD = 'post'
    # DATA = {"kind": "category", "length": 500, "offset": 0}
    # DATA = json.dumps(DATA)

    # List all the value of a specific category key on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/categories/TestSQL/list'
    # METHOD = 'post'
    # DATA = {"kind": "category", "length": 500, "offset": 0}
    # DATA = json.dumps(DATA)

    # # Get a category key on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/categories/AppType'
    # METHOD = 'get'
    # DATA = {}
    # DATA = json.dumps(DATA)

    # Get a category value on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/categories/AppType/Apache_Spark'
    # METHOD = 'get'
    # DATA = {}
    # DATA = json.dumps(DATA)

    # Create/Update a category value on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/categories/TestSQL/AdamHsuValue01'
    # METHOD = 'put'
    # DATA = {"value": "AdamHsuValue01"}
    # DATA = json.dumps(DATA)


    ########## hosts
    # List hosts on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/hosts/list'
    # METHOD = 'post'
    # DATA = {"kind": "host", "length": 500, "offset": 0}
    # DATA = json.dumps(DATA)


    ########## PE
    # List all hosts on PE (more details)
    # URL = 'https://10.45.130.207:9440/PrismGateway/services/rest/v2.0/hosts'
    # METHOD = 'get'
    # DATA = {}

    # List all VMs on PE (less details)
    # URL = 'https://10.45.130.207:9440/PrismGateway/services/rest/v2.0/vms/'
    # METHOD = 'get'
    # DATA = {}


    ########## recovery_plan_jobs
    # List all recovery_plan_jobs on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/recovery_plan_jobs/list'
    # METHOD = 'post'
    # DATA = {"kind": "recovery_plan_job", "length": 500, "offset": 0}
    # DATA = json.dumps(DATA)


    ########## restore
    # Joice's PC => 10.45.233.51
    # Nutanx mac => "mac_address": "9A:1A:24:90:80:54",
    # Random mac address => "mac_address": "D3:AC:11:32:A3:53",
    # Restore a RP on PC (categories must already exist in PC) [url => top level RP id][vm_recovery_point... => vm_level_RP_id]

    # URL = 'https://10.45.233.51:9440/api/nutanix/v3/recovery_points/fdce2427-7b80-4a91-91a0-158e06a23d27/restore'
    # METHOD = 'post'
    # DATA = {
    #   "vm_list": [
    #     {
    #       "vm_recovery_point_reference": {
    #         "kind": "vm_recovery_point",
    #         "uuid": "4db8fc16-bae8-471e-bc7e-1b24c0e457f6"
    #       },
    #       "vm_spec": {
    #         "name": "DEBUG_R_ADAM_VM",
    #         "resources": {
    #           "nic_list": [
    #             {
    #               "nic_type": "NORMAL_NIC",
    #               "uuid": "12345678-9abc-def0-1234-56789abcdef0",
    #               "ip_endpoint_list": [
    #                 {
    #                   "type": "ASSIGNED"
    #                 }
    #               ],
    #               "vlan_mode": "ACCESS",
    #               "mac_address": "50:6B:8D:d5:7e:8d",
    #               "subnet_reference": {
    #                 "kind": "subnet",
    #                 "name": "vlan_override_777",
    #                 "uuid": "0a79cf54-1842-42ee-9733-c1598368d238"
    #               },
    #               "is_connected": True,
    #               "trunked_vlan_list": []
    #             }
    #           ]
    #         }
    #       },
    #       "metadata": {
    #         "categories_mapping": {
    #             "TestSQL":  ["Nutest"]
    #         }
    #       }
    #     }
    #   ]
    # }
    # DATA = json.dumps(DATA)

    ########## subnets
    # URL = 'https://10.45.139.32:9440/api/nutanix/v3/subnets/550c924d-b8bd-4491-a958-a98cf2d33e65'
    # METHOD = 'delete'
    # DATA = {}
    # DATA = json.dumps(DATA)

    ########## task
    # Get a task on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/tasks/4bdab2e8-3608-44b8-bbe4-a52f81bc2788'
    # METHOD = 'get'
    # DATA = {}


    ########## vms
    # List all vm's on PC
    URL = 'https://10.40.184.147:9440/api/nutanix/v3/vms/list'
    METHOD = 'post'
    DATA = {"kind": "vm", "length": 500, "offset": 0}
    DATA = json.dumps(DATA)

    # Create a vm
    # URL = 'https://10.45.233.51:9440/api/nutanix/v3/vms'
    # METHOD = 'post'
    # DATA = {
    #   "metadata": {
    #     "kind": "vm"
    #   },
    #   "spec": {
    #     "name": "CCC_MAC_ADDRESS_VM",
    #     "resources": {
    #       "nic_list": [
    #         {
    #           "mac_address": "D3:AC:11:32:A3:53",
    #           "subnet_reference": {
    #             "kind": "subnet",
    #             "name": "vlan_override_777",
    #             "uuid": "0a79cf54-1842-42ee-9733-c1598368d238"
    #           }
    #         }
    #       ]
    #     }
    #   }
    # }
    # DATA = json.dumps(DATA)

    # Get a vm on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/vms/dbb98361-271f-5dd8-ae97-167a1beea0fb'
    # METHOD = 'get'
    # DATA = {}
    # DATA = json.dumps(DATA)

    # Delete a vm on PC
    # URL = 'https://10.40.184.30:9440/api/nutanix/v3/vms/191f0539-2c89-54ff-ac81-a1a79bc61677'
    # METHOD = 'delete'
    # DATA = {}
    # DATA = json.dumps(DATA)


    res = send_req(url=URL, method=METHOD, data=DATA)
    print
    print 'content => ', json.dumps(json.loads(res.content), indent=2)
    print 'status => ', res
    with open("TEMP_http_post_try.josn", "w") as fp:
        json.dump(json.loads(res.content), fp, indent=2)
    print "content saved in => TEMP_http_post_try.json"
