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
    URL = 'https://10.40.184.60:9440/api/nutanix/v3/recovery_points/4cef6bd4-3134-4cf7-ba80-8ff1bf12b191/restore'
    METHOD = 'post'
    DATA = {
      "vm_list": [
        {
          "vm_recovery_point_reference": {
            "kind": "vm_recovery_point",
            "uuid": "4dc1fac4-fbfd-46f8-bbd3-c395a81fefcf"
          },
          "vm_spec": {
            "name": "R_DEBUG_ADAM_VM"
          },
          "metadata": {
            "categories_mapping": {
              #"MartialArt": ["Judo"] #Category not existing on PC
              "AccessType": ["Internet"] #Category existing on PC
            }
          }
        }
      ]
    }
    DATA = json.dumps(DATA)

    res = send_req(url=URL, method=METHOD, data=DATA)
    print
    print 'content => ', json.dumps(json.loads(res.content), indent=2)
    print 'status => ', res
    with open("TEMP_http_post_try.josn", "w") as fp:
        json.dump(json.loads(res.content), fp, indent=2)
    print "content saved in => TEMP_http_post_try.json"
