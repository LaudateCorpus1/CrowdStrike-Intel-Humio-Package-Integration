import logging


#Set Logging Level and file name
CS_indicators_log_level = logging.DEBUG
log_file = 'CrowdStrikeIntelIndicators2Humio.log'

#Code version - do not alter
CS_indicators_version = '1.0'

#CrowdStrike Intel Indicators Configuration

#####CrowdStrike API credential with Intel Indicators Scope
CS_indicators_client_id="",
CS_indicators_client_secret=""

#indicates the CrowdStrike cloud to connect to, this URL can be found in the Falcon UI
CS_indicators_base_url = 'https://api.crowdstrike.com'

#Intel API parameter full syntax ***'limit' should not exceed 9999 and 'sort' should NOT be modified ***:
#PARAMS = {"offset": integer, "limit": 5000, "sort": "_marker", "filter": "string", "q": "string", "fields": ["string", "string"]}

#Intel API parameters example, ***'limit' and 'sort' should NOT be modified ***
CS_indicators_params = {'limit': 4000, 'include_deleted': True, 'filter':"_marker:>'1596041856f59b3c30f70afcfd023212b5e1fe96ef'",'sort': '_marker.asc'}


#####Humio HEC configuration

#Humio URL
Humio_base = ''
HumioHECurl = Humio_base+'/api/v1/ingest/hec/raw'
#sample full HEC URL = http://192.168.1.229:8080/api/v1/ingest/hec/raw

#Humio HEC Token
HumioHECtoken_IntelIndicators = ''

#Header Content Type
HumioHECContent_IntelIndicators  = "{'Content-Type': 'application/json', 'Accept':'application/json'}"


#Verify certificate - only set to 'False' in a controlled test enviroment
HumioHECVerify_IntelIndicators = True



