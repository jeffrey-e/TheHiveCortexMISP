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

#Define the main logger
logger = logging.getLogger("QTHI")

#Create epoch in ms current timestamp. Required for comparisons
current_time = time.time() * 1000

class QRadarRequests:
    """
        Python API for QRadar

        :param config
    """
    def __init__(self, config, ReportConfig=False):
    
        #Basic requests config
        self.url = config['url']
        self.key = config['key']
        self.proxies = config['proxies']
        self.verify = config['verify']
        if not self.verify:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(category=SubjectAltNameWarning)
        
        #Headers
        self.headers = {'SEC': self.key}
        self.headers['Accept'] = 'application/json'
        
        # Load config for reports
        if ReportConfig:
            self.ReportConfig = ReportConfig
        
    #Function to make a human readable date format
    def convert_eepoch(self, timestamp):
        return datetime.datetime.fromtimestamp(timestamp / 1000)
    
    def qradar_request(self, http_type, uri, response_code):
        #Build url
        request = self.url + uri
        logger.debug('{} request url: {}'.format(http_type,request))
        
        #Perfom request with exception handler
        try:
            #Decide what request type should be made
            if http_type == "get":
                response = requests.get(request, headers=self.headers,
                                    proxies=self.proxies,
                                    verify=self.verify)
            if http_type == "post":
                response = requests.post(request, headers=self.headers,
                                    proxies=self.proxies,
                                    verify=self.verify)
            #Parse json from response
            self.qr_response = response.json()
            
            #Check response code and act accordingly
            if response.status_code == response_code:
                logger.debug('Response: %s' % response.text)
                return self.qr_response
            else:
                logger.error("QRadar reponse code: {} error: {}".format(response.status_code,self.qr_response))
        except requests.exceptions.RequestException as e:
            logger.error("Error: {}".format(e))

    # Generic table builder for The Hive using Markdown. 
    # Expected argument types: {columns: list or tuple with column names, message: string, event: dict with column name as keys and corresponding value)
    # Returns the original string with appended Markdown table syntax 
    def create_table(self, message, event):
        #Create a header when message is empty
        #get column names using the event keys
        columns = list(event.keys())
        if not message:
            message = "\n"
            # Filling header with column names
            for column_name in columns:
                message = message + "| " + column_name + " "
            # add last pipe and newline
            message += "|\n"
            # Finish header markup
            number_of_columns = len(columns)
            for column in range(number_of_columns):
                message = message + "| -- "
            # add last pipe and newline
            message += "|\n"
            return message
        #Construct table row
        for column_name in columns:
            message = message + "| " + str(event[column_name]) + " "
            # add last pipe and newline
        message += "|\n"
        
        return message
    
    # Generic QRadar query function
    def run_query(self, query):
        #start query in qradar
        self.start_query = self.qradar_request("post", query, 201)
        #find search id for retrieval of results
        self.query_id = self.start_query["search_id"]
        #polling API to check if query results are done
        while True:
            self.query_status = self.qradar_request("get","/api/ariel/searches/{}".format(self.query_id), 200)
            # continue with this function if results are completed, else wait 10 seconds
            if self.query_status["status"].upper() == "COMPLETED":
                break
            time.sleep(10)
        #retrieving query results
        self.events = self.qradar_request("get","/api/ariel/searches/{}/results".format(self.query_id), 200)
               
        return self.events  
        
    #Create a function to standardize the message creation through different options
    def create_lse_message(self, message, log_source_info):
        #Print a header when message is empty
        if not message:
            message = '''
| Last Event | Id | Status | Log source | Description | Group ids | Auto discovered |
| ---------- | -- | ------ | ---------- | ----------- | :-------: | :-------------: |
'''
        return message + "| {} | {} | {} | {} | {} | {} | {} |\n".format(
        log_source_info['last_event_time_normalized'],
        log_source_info['id'],
        log_source_info['status']['status'],
        log_source_info['name'],
        log_source_info['description'],
        log_source_info['group_ids'],
        log_source_info['auto_discovered'])
    
    def get_log_sources_in_error(self, report_type, criticality):
        
        """
        Get all offenses or retrieve by Id
        :param id:
        :type id: int
        :return: response()
        :rtype: dict
        """
        
        self.report_description = self.ReportConfig[report_type]['description'] 
        
        logger.info("Retrieving {} within QRadar".format(self.report_description))
        
        #Build the request addres
        self.address = self.ReportConfig[report_type]['uri'] + '?' + self.ReportConfig[report_type]['params']
        #Perform a request for all log sources in error
        self.log_sources_found = self.qradar_request("get", self.address, 200)
        #Counter for amount of log sources
        self.log_source_count = 0
        
        #Define veriable
        self.log_source_summary = ""
        
        #Loop through found log sources
        for self.log_source_in_error in self.log_sources_found:
            self.log_source_in_error['last_event_time_normalized'] = self.convert_eepoch(self.log_source_in_error['last_event_time'])
            
            #Retrieve all log sources that are not receiving logs for longer than 1 day but less than a week
            self.time_difference = current_time - self.log_source_in_error['last_event_time']
            #print "ls:{} td: {}".format(self.log_source_in_error['name'], self.time_difference)
            #print "ct: {} let: {}".format(current_time ,self.log_source_in_error['last_event_time'])
            if self.time_difference > 86400000 and self.time_difference < 604800000:
            #ls:WindowsAuthServer@B0073100 td: 10485739599.6
                if criticality == "standard":
                    self.log_source_count += 1
                    self.log_source_summary = self.create_lse_message(self.log_source_summary, self.log_source_in_error)
            
                #Check for critical groups only
                if criticality == "critical":
                    #Define critical groups
                    self.critical_log_source_groups = self.ReportConfig[report_type]['critical_log_sources']
                    #Loop through log source groups
                    for self.group in self.log_source_in_error['group_ids']:
                        #If a match is found, set value to True
                        if self.group in self.critical_log_source_groups:
                            self.critical_log_source = True
                            #If critical, add to summary
                            if self.critical_log_source:
                                self.log_source_count += 1
                                self.log_source_summary = self.create_lse_message(self.log_source_summary, self.log_source_in_error)
                                
                    if self.log_source_count == 0:
                        return False
                            
            #Retrieve all log sources in error
            if criticality == "all":
                self.log_source_count += 1
                self.log_source_summary = self.create_lse_message(self.log_source_summary, self.log_source_in_error)
        
        #Create a meaningful description
        self.description = "Found {} {} that need attention.".format (self.log_source_count, self.report_description)
        #Provide attachment path with distinguishing between critical and standard reports
        attachment_path = '/tmp/ls_attachment_{}.csv'.format(criticality) 
        
        #Create Alert object
        self.lseAlert = {}
        self.lseAlert['title'] = "{} log sources in ERROR state".format(criticality.upper())
        #Append the actual log sources in error to the description defined above
        self.lseAlert['description'] = self.description + "\n" + self.log_source_summary
        return self.lseAlert
    
    # Function for getting event based reports
    def get_event_report(self, report_type, criticality):
    
        self.report_description = self.ReportConfig[report_type]['description'] 
        
        logger.info("Retrieving {} within QRadar".format(self.report_description))
        
        # Load query params from config and encode into url
        self.query_expression = self.ReportConfig[report_type]['query']
        self.query_uri = self.ReportConfig[report_type]['uri']
        self.query = self.query_uri + self.query_expression 
        
        # Run query and get results
        self.events = self.run_query(self.query)
        
        #Counter for amount of query results
        self.events_count = len(self.events['events'])
        
        #Define variable
        self.events_summary = ""
        
        #Loop through found events and build a table
        for self.event in self.events['events']: 
            self.events_summary = self.create_table(self.events_summary, self.event)
        
        #Create a meaningful description
        self.description = "Found {} {} events that need attention.\n".format (self.events_count, self.report_description)
        #Provide attachment path 
        attachment_path = '/tmp/apr_attachment_{}.csv'.format(report_type)   
        
        #Create Alert object
        self.lseAlert = {}
        self.lseAlert['title'] = "{} events".format(self.report_description)
        #Append the actual events to the description defined above
        self.lseAlert['description'] = self.description + "\n" + self.events_summary
        
        return self.lseAlert
