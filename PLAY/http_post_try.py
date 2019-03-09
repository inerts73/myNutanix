import json
from requests import Session

session = Session()
r = session.request(method='get', url='https://developer.github.com/v3/activity/events/#list-public-events')
r = session.get('https://developer.github.com/v3/activity/events/#list-public-events')
print r

########################################################################

URL = 'https://10.40.184.30:9440/api/nutanix/v3/recovery_plan_jobs/list'
PARAMS = {}

DATA = '{"kind": "recovery_plan_job", "length": 500, "offset": 0}'
# DATA = json.dumps({
#         'kind': 'recovery_plan_job',
#         'offset': 0,
#         'length': 500
#       })

HEADERS_VALUE = {'content-type': 'application/json;charset=UTF-8', 'Accept':
    'application/json, text/javascript, */*; q=0.01'}
AUTH = ('admin', 'Nutanix.123')
TIMEOUT = 30
VERIFY = False

# response = session.request(url=URL, method='post', params=PARAMS,
#                            headers=HEADERS_VALUE, auth=AUTH, timeout=TIMEOUT,
#                            data=DATA, verify=False)

session.auth = AUTH
response = session.post(url=URL,
                        headers=HEADERS_VALUE,
                        data=DATA,
                        verify=False)

print
print 'status => ', response.status_code
print 'content => ', response.content


