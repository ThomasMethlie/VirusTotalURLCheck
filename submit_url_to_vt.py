import simplejson
import urllib
import urllib2
url = "https://www.virustotal.com/vtapi/v2/url/scan"
parameters = {"url": "http://www.virustotal.com", "apikey": "-- YOUR API KEY --"}
data = urllib.urlencode(parameters)
req = urllib2.Request(url, data)
response = urllib2.urlopen(req)
json = response.read()
print json
