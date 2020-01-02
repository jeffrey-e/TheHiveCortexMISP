#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import requests
import sys
import datetime
import logging
import json
import redis

class QRadarApi():
    """
        Python API for QRadar

        :param config
    """

    def __init__(self, config):
        self.url = config['url']
        self.key = config['key']
        self.proxies = config['proxies']
        self.verify = config['verify']
        #self.username = config.get('username', None)
        #self.password = config.get('password', None)
        
        self.redis_sip = redis.StrictRedis(host="localhost", port=6379, db=0)
        self.redis_dip = redis.StrictRedis(host="localhost", port=6379, db=1)

    def request_identifier(self, request):
        try:
            response = requests.get(request, headers=self.headers,
                                proxies=self.proxies,
                                verify=self.verify)
            if response.status_code == 200:
                return response.json()
            else:
                logging.debug('API QRadar - raw error output: {}'.format(response.raw.read()))
                return False
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def resolve_identifiers(self, raw_input):
        for offense in raw_input:
            logging.debug("Finding source IP addresses for %s" % offense['id'] )
            #Find source ip address ids in the offense
            source_ip_ids = offense['source_address_ids']
            source_ips = []
            #loop through the found identifiers
            for source_ip_id in source_ip_ids:
                #Check if IP is in Redis
                source_ip = self.redis_sip.get(source_ip_id)
                logging.debug("Found %s for id:%s in redis" % (source_ip,source_ip_id ))
                if source_ip == None:
                    #lookup the identifier to resolve the ip address
                    req = self.url + "/api/siem/source_addresses/{}?fields=source_ip".format(source_ip_id)
                    resp = self.request_identifier(req)
                    source_ip = resp['source_ip']
                    source_ips.append(source_ip)
                    self.redis_sip.set(source_ip_id, source_ip, 604800)
                    logging.debug("Found %s for id:%s" % (source_ip,source_ip_id ))
                else:
                    source_ips.append(source_ip)
            offense['source_address_ips'] = source_ips
            
            logging.debug("Finding target IP addresses for %s" % offense['id'] )
            #Find target ip address ids in the offense
            destination_ip_ids = offense['local_destination_address_ids']
            destination_ips = []
            for destination_ip_id in destination_ip_ids:
                #Check if IP is in Redis
                destination_ip = self.redis_dip.get(destination_ip_id)
                logging.debug("Found %s for id:%s in redis" % (destination_ip,destination_ip_id ))
                if destination_ip == None:
                    req = self.url + "/api/siem/local_destination_addresses/{}?fields=local_destination_ip".format(destination_ip_id)
                    resp = self.request_identifier(req)
                    destination_ip = resp['local_destination_ip']
                    destination_ips.append(destination_ip)
                    self.redis_dip.set(destination_ip_id, destination_ip, 604800)
                    logging.debug("Found %s for id:%s" % (destination_ip,destination_ip_id ))
                else:
                    destination_ips.append(destination_ip)
            offense['local_destination_address_ips'] = destination_ips
            
            logging.debug("Finding offense type for %s" % offense['id'] )
            #Find target ip address ids in the offense
            offense_type_id = offense['offense_type']
            req = self.url + "/api/siem/offense_types/{}?fields=name".format(offense_type_id)
            resp = self.request_identifier(req)
            offense_type = resp['name']
            logging.debug("Found offense type %s for id:%s" % (offense_type,offense_type_id ))
            #Spaces are not supported by The Hive
            offense['offense_type'] = offense_type #.replace(" ", "_")
            

    def response(self, status, content):
        """
        status: success/failure
        content: dict
        return: dict
        """
        return {'status': status, 'data': content}

    def get_offenses(self, id):

        """
        Get Alert by Id
        :param id:
        :type id: int
        :return: response()
        :rtype: dict
        """

        #Headers
        self.headers = {'SEC': self.key}
        self.headers['Accept'] = 'application/json'
        
        if id == None:
            req = self.url + "/api/siem/offenses?filter=status=OPEN&fields=description,event_count,flow_count,source_address_ids,inactive,start_time,last_updated_time,id,categories,offense_type,offense_source,local_destination_address_ids"
        else:
            #If multiple entries are provided, only use the first one
            id = id[0]
            req = self.url + "/api/siem/offenses/{}?&fields=description,event_count,flow_count,source_address_ids,inactive,start_time,last_updated_time,id,categories,offense_type,offense_source,local_destination_address_ids".format(id)
        
        logging.debug("Retrieving offenses within QRadar")
        try:
            resp = requests.get(req, headers=self.headers,
                                proxies=self.proxies,
                                verify=self.verify)
            #When a single ID is given, the response must be manually put in a list
            if id:
                qr_response = []
                qr_response.append(resp.json())
            else:
                qr_response = resp.json()
            if resp.status_code == 200:
                logging.debug("Found %i QRadar offenses, resolving id's" % len(qr_response))
                self.resolve_identifiers(qr_response)
                return self.response("success", qr_response)
            else:
                return self.response("failure", qr_response)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))