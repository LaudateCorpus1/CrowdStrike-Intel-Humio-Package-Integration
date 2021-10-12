#!/usr/bin/env python

#python imports
import requests
import sys
import logging
from humiolib.HumioClient import HumioIngestClient

#local imports
import CrowdStrikeIntelIndicators2HumioConfig as config

class Send_to_HEC():

    def send_to_HEC(event_data):

        HumioHECurl = config.HumioHECurl
        HumioHECtoken =config.HumioHECtoken_IntelIndicators
        log_level = config.CS_indicators_log_level

        version = '1.0'
        logging.basicConfig(filename=config.log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=log_level)
        
        logging.info('IntelIndicators2Humio v' + version + ' HEC: Sending data to Humio HEC')

        try:

            header = {"Authorization": "Bearer " + HumioHECtoken, "Content-Type": config.HumioHECContent_IntelIndicators} 
            r = requests.post(url=HumioHECurl, headers=header, data= event_data.encode('utf-8'), verify=config.HumioHECVerify_IntelIndicators , timeout=300)
            transmit_result = r.status_code
            logging.info('IntelIndicators2Humio v' + version + ' HEC: Transmission status code for data push to HEC= '+ str(transmit_result))
            logging.info('IntelIndicators2Humio v' + version + ' HEC: Transmission results for data push to HEC= '+ str(r.json))

        except requests.exceptions.RequestException as e:
            error=str(e)
            logging.info('IntelIndicators2Humio v' + version + ' HEC: Unable to evaluate and transmit sensor_data event: Error: ' + error)
            try:
                sys.exit('IntelIndicators2Humio v' + version + ' HEC: This is fatal error, please review and correct the issue - CrowdStrike Intel Indicators to Humio is shutting down')
            except:
                pass
