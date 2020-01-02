#!/usr/bin/env python3
# coding: utf-8

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert
import os
import socket
import logging
import time

class TheHiveRequests:

    def __init__(self, config, ReportConfig):
        #Define the main logger
        self.logger = logging.getLogger("QTHI")
        self.config = config
        #Load config for reports
        self.ReportConfig = ReportConfig

        #Timestamp
        self.current_time = int(round(time.time() * 1000))
        
        #Assign The Hive API class
        self.thapi = TheHiveApi(self.config.get('url', None),
                           self.config.get('key'),
                           self.config.get('password', None),
                           self.config.get('proxies'),
                           self.config.get('verify'))

    #Allow stringed output when needed
    def __repr__(self, alert):
        return str(alert.__dict__)

    #Function to prepare an alert object that is required to perform Alert based action within The Hive	
    def prepare_alert(self, content, alert_type):
        """
        convert a QRadar alert into a TheHive alert

        :param content: QRadar Alert
        :type content: dict
        :return: Thehive alert
        :rtype: thehive4py.models Alerts
        """
        
        #Defined tags that should be present in the alert
        case_tags = ["src:QRadar"]
                               
        ''' CHANGE NOT DONE ''' 
        ''' Added APR and RESPC alert type. Still needs a case template and argument adjustment (severity, source etc). Importing the Alert function arguments from config file
        Please do not forget the change on line 290'''
        if alert_type in ["lse", "apr", "respc"]:
            
            case_tags.append(alert_type)
            #Build alert as object defined in TheHive4Py models
            alert = Alert(title=content.get("title"),
                          tlp=2,
                          tags=case_tags,
                          severity=int(content.get('severity', self.ReportConfig[alert_type]['severity'])),
                          description=content.get('description'),
                          type='{} report'.format(alert_type.upper()),
                          source='QRadar',
                          caseTemplate=self.ReportConfig[alert_type]['case_template'],
                          sourceRef="qrpt-{}-{}".format(alert_type, str(self.current_time)))

            self.logger.info("Alert built for {}".format(self.ReportConfig[alert_type]['description']))
            self.logger.debug(str(alert))
            
        return alert

    #Function to check if the alert that has been created contains new/different data in comparison to the alert that is present
    def check_if_updated(self, current_a, new_a):
        for item in sorted(new_a):
            #Skip values that are not required for the compare
            if item is "date":
                continue
            #Artifacts require special attention
            if item is "artifacts":
                #If the array is of different size an update is required
                if not len(current_a[item]) == len(new_a[item]):
                    self.logger.info("Length mismatch detected: old length:%s, new length: %s" % (len(current_a[item]),len(new_a[item])))
                    return True
                
                #loop through the newly created alert array to extract the artifacts and add them so a separate variable
                for i in range(len(new_a[item])):
                    vars_current_artifacts = current_a[item][i]
                    vars_new_artifacts = vars(new_a[item][i])
                    
                    #For each artifact loop through the attributes to check for differences
                    for attribute in vars_new_artifacts:
                        if vars_current_artifacts[attribute] != vars_new_artifacts[attribute]:
                            self.logger.debug("Change detected for %s, new value: %s" % (vars_current_artifacts[attribute],vars_new_artifacts[attribute]))
                            self.logger.debug("old: %s, new: %s" % (vars_current_artifacts,vars_new_artifacts))
                            return True
                continue
                
            if item is "tags":
                #loop through the newly created alert array to extract the tags and add them so a separate variable
                for i in range(len(new_a[item])):
                    i = int(i)
                    vars_current_tags = current_a[item][i]
                    vars_new_tags = new_a[item][i]
                
                    #For each tag loop through the new attributes to check for missing tags. The chances are zero to none that a tag will be removed, so this check is skipped
                    for tag in vars_new_tags:
                        if not tag in vars_current_tags:
                            self.logger.debug("Change detected for %s, new value: %s" % (vars_current_tags,str(tag)))
                            return True
                continue
             
            #Match other items of the new alert to the current alert (string based)
            if str(current_a[item]) != str(new_a[item]):
                self.logger.debug("Change detected for %s, new value: %s" % (item,str(new_a[item])))
                return True
        return False

    #Function to actually create a new alert in The Hive    
    def create_th_alerts(self, alerts, alert_type):
        """
        :param alerts: List of alerts
        :type alerts: list
        :return: create TH alert
        """
        
        # CHANGE        
        if alert_type in ["lse", "apr", "respc"]:
            #Loop through all alerts to be created
            for alert in alerts:
                self.logger.info("Creating alert {} for {} report".format(self.current_time, alert_type.upper()))
                response = self.thapi.create_alert(alert)
       
        #Create a default action for standard alerts    
        else:
            self.logger.info("Creating default alert")
            alert = alerts
            response = self.thapi.create_alert(alert)
        
        #Check output to handle errors
        self.logger.debug('API TheHive - status code: {}'.format(
            response.status_code))
        if response.status_code > 299:
            self.logger.error('API TheHive - raw error output: {}'.format(
                response.raw.read()))
        else:
            self.logger.debug('Posted alert %s' % self.__repr__(alert))