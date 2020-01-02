#!/usr/bin/env python
# encoding: utf-8

import time
import logging
''' CHANGE ''' 
import yaml
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CustomFieldHelper
from thehive4py.query import *

import threading
from threading import Thread
from queue import Queue

#Define the main logger
logger = logging.getLogger("QTHI")

#Define Queue/Thread settings
#Allowed concurrent threads
concurrent = 5
#Queue size
q = Queue(concurrent * 1000)

class TheHiveScheduledSearches:

    def __init__(self, TheHive, QRadar):
        #Retrieve enabled datatypes from config
        self.qr_enabled_datatypes = QRadar['enabled_datatypes']

        #Add epoch in milliseconds of current time to a variable
        self.current_time = int(round(time.time() * 1000))

        #Assign The Hive API class
        self.thapi = TheHiveApi(TheHive.get('url', None),
                           TheHive.get('key'),
                           TheHive.get('password', None),
                           TheHive.get('proxies'),
                           TheHive.get('verify'))

    #Generic function to check the response from the hive
    def check_response(self, response):
        logger.debug('API TheHive - status code: {}'.format(
        response.status_code))
        if response.status_code > 299:
            logger.error('API TheHive - raw error output: {}'.format(
                response.raw.read()))
        logger.debug('Response: %s' % response.text)

    def observable_search(self):
        #Search for cases with first_searched
        logger.info('Searching for matching cases')
        self.query = Contains('customFields.firstSearched.date')
        self.response = self.thapi.find_cases(query=self.query)
        logger.debug('Response: %s' % self.response.text)

        #Compare first_searched and last_searched. If longer than 60 days. Do not search.
        for case_data in self.response.json():
            queue_item = {}
            #Create observable queue item
            queue_item['action'] = "search_observables"
            queue_item['data'] = case_data
            #Add case to the queue
            self.thapi_queue(queue_item)
        self.process_queue()
        while q.qsize() > 0:
            logger.info('Current queue size(%i)' % q.qsize())
            time.sleep(60)
        
        
    #Define the logic that makes it possible to perform asynchronous requests to The Hive in order to speed up the integration        
    def thapi_queue(self, queued_request):
        
        #Build up the queue
        logger.info('Adding action: %s to queue for: %s (Current queue length: %i)' % (queued_request['action'], queued_request['data']['id'], q.qsize()))
        q.put(queued_request)
        
        
    def process_queue(self):
        #Create the first thread
        thread_count = threading.active_count()
        if thread_count <= 1:
            logger.info('Creating thread')
            t = Thread(target=self.doWork)
            t.daemon = True
            t.start()
            logger.debug('Created thread')
          
    #Define the functionality each workers gets
    def doWork(self):
        #Build a loop that keeps the thread alive until queue is empty
        while not q.empty():
            #Build up the threads
            thread_count = threading.active_count()
            #Make sure that the thread count is lower than configured limit and is lower than the queue size
            if thread_count < concurrent and thread_count < q.qsize():
                new_thread_count = thread_count + 1
                logger.info('Current queue size(%i) allows more threads. Creating additional thread: %i' % (q.qsize(), new_thread_count))
                t = Thread(target=self.doWork)
                t.daemon = True
                t.start()
                logger.debug('Created thread: %i' % new_thread_count)
            
            #Retrieve a queued item
            queued_item = q.get()
            
            #Handle a queued item based on its provided action
            if queued_item['action'] == "search_observables":
                logger.info('Working on %s from queue, caseid: %s' % (queued_item['action'], queued_item['data']['id']))
        
                case_data = queued_item['data']
                logger.debug("event: %s" % case_data)
                #Store CaseID
                caseid = case_data['id']
                
                #If the case is within scope of the search range. Perform the search
                #if (case_data['customFields']['lastSearched']['date'] - case_data['customFields']['firstSearched']['date']) < 5184000000:
                    #logger.info('Observables in case {} have not yet been searched for longer than two months. Starting analyzers'.format(case_data['id']))
                self.response = self.thapi.get_case_observables(caseid)

                #Perform a search for ioc's per case in the RS search results (Trigger Cortex Analyzer)
                for observable in self.response.json():
                    searched_for = False
                    logger.debug("observable: %s" % observable)
                    logger.debug("current_time %s, observable_time %s" % (self.current_time, observable['startDate'] ))
                    #Check if observables are not older than 2 months or 6 months for TLP:RED
                    if (((self.current_time - observable['startDate']) < 5184000000) or (observable['tlp'] == 3 and ((self.current_time - observable['startDate']) < 15552000))):
                        self.searchtype = observable['dataType']
                        if self.searchtype in self.qr_enabled_datatypes:
                            self.supported_observable = observable['_id']
                            
                            #Trigger a search for the supported ioc
                            logger.info('Launching analyzers for observable: {}'.format(self.supported_observable))
                            self.response = self.thapi.run_analyzer("Cortex-intern", self.supported_observable, "IBMQRadar_Search_Automated_0_1")
                            self.check_response(self.response)
                            searched_for = True
                    
                if searched_for:
                    #Add customFields firstSearched and lastSearched
                    #Create a Case object? Or whatever it is
                    self.case = Case()
                    
                    #Add the case id to the object
                    self.case.id = caseid
                    
                    #Debug output
                    logger.info('Updating case %s' % self.case.id)

                    #Define which fields need to get updated
                    fields = ['customFields']
                    
                    #Retrieve all required attributes from the alert and add them as custom fields to the case
                    self.customFields = CustomFieldHelper()\
                        .add_date('firstSearched', case_data['customFields']['firstSearched']['date'])\
                        .add_date('lastSearched', self.current_time)\
                        .build()
                    
                    #Add custom fields to the case object
                    self.case.customFields = self.customFields

                    #Update the case
                    self.response = self.thapi.update_case(self.case,fields)
                    self.check_response(self.response)
                    
        logger.info("Queue is empty, nothing left to do")