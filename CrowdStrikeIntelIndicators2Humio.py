#!/usr/bin/env python

#python imports
from falconpy.api_complete import APIHarness
import logging
import requests
import json
#import datetime as datetime
#from collections import defaultdict
import sys

#local imports
from Send2HumioHEC import Send_to_HEC as humio
import CrowdStrikeIntelIndicators2HumioConfig as config



class CS_Intel_Indicators_Humio():
    def get_cs_intel(self):
        log_level = config.CS_indicators_log_level
        indicators = []
        version = config.CS_indicators_version
        #set up logging information
        logging.basicConfig(filename=config.log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)
        logging.info('IntelIndicators2Humio v' + version + ': CrowdStrike Intel Indicators to Humio is starting')

        #CrowdStrike falconpy uber class config 
        falcon = APIHarness(client_id = config.CS_indicators_client_id, client_secret = config.CS_indicators_client_secret, base_url=config.CS_indicators_base_url)
        
        #get initial set of parameters for indicator API call
        PARAMS = config.CS_indicators_params

        #evaluate if there's data in the tracker file to use as a starting point
        with open ('CS_Intel_to_Humio_Tracker', 'a+') as t:
            t.seek(0)
            read=t.read()
            tracker=read.split('\n')
            if len(tracker) == 0:
                logging.info('IntelIndicators2Humio v' + version + ': Tracker file is empty')
                pass
            else:
                logging.info('IntelIndicators2Humio v' + version + ': This is last marker collected per the tracker: ' + tracker[-1])
                PARAMS['filter']="_marker:>'"+tracker[-1]+"'"
        
        #CrowdStrike falconpy call to the intel indicators API
        response = falcon.command("QueryIntelIndicatorEntities", parameters=PARAMS)
        status_code = str(response['status_code'])
        logging.info('IntelIndicators2Humio v' + version + ': Connection to Intel API resulted with status code: ' + str(status_code))
        intel_ind = response['body']['resources']


        #process a successful API query
        if status_code.startswith('20'):

            for i in intel_ind:
                indicators.append(i)

            if 'Next-Page' in response['headers'] and len(response['headers']['Next-Page']) > 0 :
                pagination = True
                logging.info('IntelIndicators2Humio v' + version + ': Pagination is required')
                pag_url = response['headers']['Next-Page'] 
            else:
                pagination = False
                logging.info('IntelIndicators2Humio v' + version + ': Pagination is not required')
                with open ('CS_Intel_to_Humio_Tracker', 'a+') as t:
                    last_ind = indicators[-1]
                    t.write('\n'+last_ind['_marker'])
                logging.info('IntelIndicators2Humio v' + version + ': Tracker file has been updated')

            logging.info('IntelIndicators2Humio v' + version + ': Preparing to send initial set of indicators to Humio')

            humio_data_prep= "\n".join(map(str,intel_ind))
            humio_data_prep = humio_data_prep.replace("'", '"')
            humio_data_prep = json.dumps(humio_data_prep)
            humio_data_prep = json.loads(humio_data_prep)
            humio_data_prep = humio_data_prep.replace("True", 'true')
            humio_data_conv = humio_data_prep.replace("False", 'false')

            humio.send_to_HEC(humio_data_conv)

            #continue to call API to collect addition indicators if needed
            while pagination == True:
                logging.info('IntelIndicators2Humio v' + version + ': Pagination requires additional API calls')
                
                #get OAuth2 token using falconpy for additional indicator pulls
                payload = {"client_id": config.CS_indicators_client_id, "client_secret": config.CS_indicators_client_secret}

                try:
                    response2 = falcon.command('oauth2AccessToken', data=payload)
                    oauth2_token = response2['body']['access_token']
                    status_code = str(response2['status_code'])
                    
                    logging.info('IntelIndicators2Humio v' + version + ': Connection to OAuth2 Token API resulted with status code: ' + str(status_code))

                except Exception as e:
                    logging.error('IntelIndicators2Humio v' + version + ': Unable to obtain OAuth2 token from CrowdStrike' + e.message + '  ' + e.args)
                    sys.exit('IntelIndicators2Humio v' + version + ' : Unable to obtain OAuth2 token to complete data collection, please correct any issues and try again')

                #direct API call to the endpoint returned by API
                pag_url_call = config.CS_indicators_base_url + pag_url
                next_header = {'Authorization':'Bearer ' + oauth2_token}
                next_payload = {}
                try:
                    pag_pull = requests.get(pag_url_call, headers=next_header, data=next_payload)
                    status_code = str(response2['status_code'])

                    logging.info('IntelIndicators2Humio v' + version + ': Connection to Intel API resulted with status code: ' + str(status_code))
                    pag_next = pag_pull.headers['Next-Page']
                    pag_json = pag_pull.json()
                    pag_ind = pag_json['resources']
                except Exception as e:
                    logging.error('IntelIndicators2Humio v' + version + ': Unable to obtain OAuth2 token from CrowdStrike' + e.message + '  ' + e.args)
                    sys.exit('IntelIndicators2Humio v' + version + ' : Unable to connect to next collection of indicators, please correct any issues and try again')

                logging.info('IntelIndicators2Humio v' + version + ': Preparing to send pagination set of indicators to Humio')
                #send additional intel indicator to the Humio HEC
                for i in pag_ind:
                    indicators.append(i)

                humio_data_prep_pag = "\n".join(map(str,pag_ind))
                humio_data_prep_pag = humio_data_prep_pag.replace("'", '"')
                humio_data_prep_pag = json.dumps(humio_data_prep_pag)
                humio_data_prep_pag = json.loads(humio_data_prep_pag)
                humio_data_prep_pag = humio_data_prep_pag.replace("True", 'true')
                humio_data_conv_pag = humio_data_prep_pag.replace("False", 'false')
                humio.send_to_HEC(humio_data_conv_pag)

                #record the last _marker value of the list processed
                last_ind = indicators[-1]
                logging.info('IntelIndicators2Humio v' + version + ': Recording the last marker value to tracker: last updated='+ (str(last_ind['last_updated'])) + '    _marker value= '+ str(last_ind['_marker']))
                with open ('CS_Intel_to_Humio_Tracker', 'a+') as t:
                    t.write('\n'+last_ind['_marker'])
                    logging.info('IntelIndicators2Humio v' + version + ': Tracker file was updated')

                #check for additional indicators to process and set pagination value accordingly
                if len(pag_next) > 0:
                    pagination = True
                    pag_url = pag_pull.headers['Next-Page']
                    logging.info('IntelIndicators2Humio v' + version + ': There are additional indicators for collection ')

                else:
                    pagination = False
        
        #collection completed
        logging.info('IntelIndicators2Humio v' + version + ': Indicators collection process has completed ')
        logging.info('IntelIndicators2Humio v' + version + ': Number of indicatiors process= ' + str(len(indicators)))

CSIntelIndicators2Humio = CS_Intel_Indicators_Humio()
CSIntelIndicators2Humio.get_cs_intel()