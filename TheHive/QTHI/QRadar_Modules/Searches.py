#!/usr/bin/env python
# encoding: utf-8

''' CHANGE '''
import yaml
from QRadar_Modules.Api_Requests import QRadarRequests
import sys
import os
import logging
import time
import json

#Define the main logger
logger = logging.getLogger("QTHI")

class QRadarScheduledSearches:

    def __init__(self, QRadar):
        self.qrequests = QRadarRequests(QRadar)
        self.config = QRadar

    def rs_search(self):
        #Dictionary to catch all search ids in
        self.search_dict = {}
        # for enabled_datatype in QRadar['enabled_datatypes']:
        #Define the searches that need to be performed daily

        search_config = [ 
            {
                "reference_set": "qthi-ip",
                "queries": [
                    [
                        'Source ip in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, sourceip AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-domain', aql_result) GROUP BY aql_result LAST {} DAYS".format(self.config['search_limit'])
                    ],
                    [
                        'Destination ip in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, destinationip AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-domain', destinationip) GROUP BY aql_result LAST {} DAYS".format(self.config['search_limit'])
                    ],
                    [
                        'Source ip in flows',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, sourceip AS aql_result, COUNT(*) FROM flows WHERE REFERENCESETCONTAINS('qthi-domain', aql_result) GROUP BY aql_result LAST {} DAYS".format(self.config['search_limit'])
                    ],
                    [
                        'Destination ip in flows',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, destinationip AS aql_result, COUNT(*) FROM flows WHERE REFERENCESETCONTAINS('qthi-domain', destinationip) GROUP BY aql_result LAST {} DAYS".format(self.config['search_limit'])
                    ]
                ],
                "type": "ip"
            },
            {
                "reference_set": "qthi-domain",
                "queries": [
                    [
                        'Domain in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-domain', aql_result) GROUP BY aql_result LAST {} DAYS".format(self.config['url_root_domain_field'], self.config['search_limit'] )
                    ]
                ],
                "type": "domain"
            },
            {
                "reference_set": "qthi-fqdn",
                "queries": [
                    [
                        'Fqdn in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-fqdn', aql_result) GROUP BY aql_result LAST {} DAYS".format(self.config['url_fqdn_field'], self.config['search_limit'] )
                    ]
                ],
                "type": "fqdn"
            },
            {
                "reference_set": "qthi-url",
                "queries": [
                    [
                        'Url in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-url', aql_result) GROUP BY aql_result LAST {} DAYS".format(self.config['url_field'], self.config['search_limit'] )
                    ]
                ],
                "type": "url"
            },
            {
                "reference_set": "qthi-mail",
                "queries": [
                    [
                        'Sender address in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-mail', aql_result) AND qid == {} GROUP BY aql_result LAST {} DAYS".format(self.config['mail_recipient_field'], self.config['mail_receive_qid'], self.config['search_limit'])
                    ],
                    [
                        'Recipient address in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-mail', aql_result) AND qid == {} GROUP BY aql_result LAST {} DAYS".format(self.config['mail_sender_field'], self.config['mail_send_qid'], self.config['search_limit'])
                    ]
                ],
                "type": "mail"
            },
            {
                "reference_set": "qthi-hash-md5",
                "queries": [
                    [
                        'Hash in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-hash-md5', aql_result) AND LOGSOURCETYPENAME(devicetype) == 'Sysinternals Sysmon' GROUP BY aql_result LAST {} DAYS".format(self.config['hash_md5'], self.config['search_limit'] )
                    ]
                ],
                "type": "hash"
            },
            {
                "reference_set": "qthi-hash-sha1",
                "queries": [
                    [
                        'Hash in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-hash-sha1', aql_result) AND LOGSOURCETYPENAME(devicetype) == 'Sysinternals Sysmon' GROUP BY aql_result LAST {} DAYS".format(self.config['hash_sha1'], self.config['search_limit'] )
                    ]
                ],
                "type": "hash"
            },
            {
                "reference_set": "qthi-hash-sha2",
                "queries": [
                    [
                        'Hash in logs',
                        "SELECT MIN(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS first_seen, MAX(DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm')) AS last_seen, \"{}\" AS aql_result, COUNT(*) FROM events WHERE REFERENCESETCONTAINS('qthi-hash-sha2', aql_result) AND LOGSOURCETYPENAME(devicetype) == 'Sysinternals Sysmon' GROUP BY aql_result LAST {} DAYS".format(self.config['hash_sha256'], self.config['search_limit'] )
                    ]
                ],
                "type": "hash"
            }    
        ]
                    
        for querydetails in search_config:
            # #Loop through the searches
            self.search_dict[querydetails["reference_set"]] = []
            
            if querydetails["type"] in self.config['enabled_datatypes']:
                for query in querydetails["queries"]:
                    self.rs_search_object = self.qrequests.qradar_request("post","/api/ariel/searches?query_expression={}".format(query[1]), 201)
                    logger.info("SearchID of the search(%s) %s" % (querydetails["reference_set"], self.rs_search_object['search_id']))
                    
                    #Put all search in the dict with the reference set as key
                    self.search_dict[querydetails["reference_set"]].append([query[0], self.rs_search_object['search_id'], query[1]])
            else:
                del self.search_dict[querydetails["reference_set"]]
        
        #Create a loop to wait for the searches to finish
        self.all_qr_search_completed = [False]
        self.completed_searches = []
        self.runtime = 0

        while False in self.all_qr_search_completed:
            logger.info("Checking search status...")
            self.all_qr_search_completed = []
            for search_rs,searches in self.search_dict.items():
                for running_search in searches: 
                    #Retrieve status from QRadar
                    self.results = self.qrequests.qradar_request("get", "/api/ariel/searches/{}".format(running_search[1]), 200)
                    self.qr_search_status = self.results['status']
                    logger.info("{}: Current status: {}, progress: {}".format(running_search[1], self.qr_search_status, self.results['progress']))
                    #If the search is completed... continue, else keep the loop open until the timeout is reached
                    if self.qr_search_status == "COMPLETED":
                        if not running_search[1] in self.completed_searches:
                            logger.info("{}: Completed, writing to file".format(running_search[1]))
                            #Open file to write uuids and create it, if it does not exist
                            self.uuid_work_file = open('/tmp/{}-uuid_work_file.txt.tmp'.format(search_rs),'a')
                            
                            self.all_qr_search_completed.append(True)
                            os.chmod('/tmp/{}-uuid_work_file.txt.tmp'.format(search_rs), 0o644)
                            self.uuid_work_file.write("{}\n".format(json.dumps(running_search)))
                            self.completed_searches.append(running_search[1])
                            
                            #Close the file
                            self.uuid_work_file.close()
                    elif self.runtime > self.config['search_timeout']:
                        logger.error('Search timed out. Please check "{}" manually and optimize the search if it happens a lot'.format(running_search))
                        self.all_qr_search_completed.append(True)
                    elif self.qr_search_status in ["EXECUTE", "WAIT"]:
                        self.all_qr_search_completed.append(False)
                    else:
                        logger.error('Unknown search status returned: {} Please check "{}" manually'.format(self.qr_search_status, running_search))
                        sys.exit()
            if False in self.all_qr_search_completed:
                self.sleep_in_seconds = self.config['polling_interval']
                self.runtime += self.sleep_in_seconds
                time.sleep(self.sleep_in_seconds)

        #Overwrite old files with the new tmp files
        for search_rs,searches in self.search_dict.items():
            logger.info("Moving tmp file({}) to regular file".format(search_rs))
            os.rename('/tmp/{}-uuid_work_file.txt.tmp'.format(search_rs), '/tmp/{}-uuid_work_file.txt'.format(search_rs))
        return True