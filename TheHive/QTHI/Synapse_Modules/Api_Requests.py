#!/usr/bin/env python3
# encoding: utf-8

import requests
import redis
import logging
import datetime
import time
import yaml
import urllib
from urllib3.exceptions import InsecureRequestWarning,SubjectAltNameWarning
from runpy import run_path



class SynapseRequests:
    """
        Python API for QRadar

        :param config
    """
    def __init__(self, config):
        #Define the main logger
        self.logger = logging.getLogger("QTHI")
    
        #Basic requests config
        self.url = config['url']
        self.proxies = config['proxies']
        self.verify = config['verify']
        if not self.verify:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(category=SubjectAltNameWarning)
        
        #Headers
        self.headers = {}
        self.headers['Accept'] = 'application/json'
    
    def synapse_request(self, http_type, uri, response_code):
        #Build url
        request = self.url + uri
        self.logger.info('Initiating {} request url: {}'.format(http_type,request))
        
        #Perfom request with exception handler
        try:
            #Decide what request type should be made
            if http_type == "get":
                self.response = requests.get(request, headers=self.headers,
                                    proxies=self.proxies,
                                    verify=self.verify)
            if http_type == "post":
                self.response = requests.post(request, headers=self.headers,
                                    proxies=self.proxies,
                                    verify=self.verify)
            #Parse json from response
            self.synapse_response = self.response.json()
            
            #Check response code and act accordingly
            if self.response.status_code == response_code:
                self.logger.debug('Response: %s' % self.response.text)
                return self.synapse_response
            else:
                self.logger.error("Synapse reponse code: {} error: {}".format(self.response.status_code,self.synapse_response))
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error("Error: {}".format(e))
            return False
