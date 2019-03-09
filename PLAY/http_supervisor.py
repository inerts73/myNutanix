import urllib2

url = 'http://10.4.150.5:14113/api/v1/callbacks/9'
request = urllib2.Request(url)
request.add_header('Content-Type', 'application/json')
# json_data = '{"pid": 1554, "supervisor_eid": 0}'
json_data = '{}'
request.add_data(json_data)
response = urllib2.urlopen(request)
print response.getcode()