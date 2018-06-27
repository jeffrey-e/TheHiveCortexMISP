#!/usr/bin/env python3
# coding: utf-8

from config import TheHive
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact
import logging
import json
import hashlib
import socket

#Allow stringed output when needed
def __repr__(self):
    return str(self.__dict__)

def resolve_ip(address):
    try:
        ptr = socket.gethostbyaddr(address)
    except socket.error as e:
        logging.debug("Error when resolving %s: %s" % (address, e))
        return False
    return ptr[0]

def add_tags(tags, content):

    """
    add tag to tags

    :param tags: existing tags
    :type tags: list
    :param content: string, mainly like taxonomy
    :type content: string
    """
    t = tags
    
    #Loop through tags to create a proper list, tagged with a shortname for the source application
    for newtag in content:
        t.append("QR_offense:{}".format(newtag))
    return t

def add_alert_artifact(artifacts, dataType, data, tags, tlp):
    """
    :param artifacts: array
    :param dataType: string
    :param data: string
    :param tags: array
    :param tlp: int
    :return: array
    :rtype: array
    """

    return artifacts.append(AlertArtifact(tags=tags,
                                          dataType=dataType,
                                          data=data,
                                          message="From QRadar",
                                          tlp=tlp)
                            )
                            
def init_artifact_tags(artifact_type):
    """
    param content:
    type content:
    return: list of tags
    rtype: array
    """
    if artifact_type == "source_ip":
        artifact_tags = ["src:QRadar", "QR:Source Hostname"]
    if artifact_type == "source_hostname":
        artifact_tags = ["src:QRadar", "QR:Source Hostname"]
    if artifact_type == "destination_ip":
        artifact_tags = ["src:QRadar", "QR:Destination Hostname"]
    if artifact_type == "destination_hostname":
        artifact_tags = ["src:QRadar", "QR:Destination Hostname"]

    return artifact_tags

def prepare_artifacts(content):
    """
    param content: QRadar offense
    type content: dict
    return: list AlertArtifact
    rtype: array
    """
    
    #Parse the content of a QRadar offense to parse the observables
    artifacts = []
    if content.get('source_address_ips'):
        for source_ip in content.get('source_address_ips'):
            add_alert_artifact(artifacts, "ip", source_ip,init_artifact_tags('source_ip'),2)
            source_hostname = resolve_ip(source_ip)
            if source_hostname:
                add_alert_artifact(artifacts, "domain", source_hostname,init_artifact_tags('source_hostname'),2)
    if content.get('local_destination_address_ips'):
        for destination_ip in content.get('local_destination_address_ips'):
            #Prevent duplicate addresses. Source IP is dominant above Destination IP regarding observables as Source IP should always be present
            if not destination_ip in content.get('source_address_ips'):
                add_alert_artifact(artifacts, 'ip', destination_ip,init_artifact_tags('destination_ip'),2)
                destination_hostname = resolve_ip(destination_ip)
                if destination_hostname:
                    add_alert_artifact(artifacts, "domain", destination_hostname,init_artifact_tags('destination_hostname'),2)
    return artifacts
	
def prepare_alert(content):
    """
    convert a QRadar alert into a TheHive alert

    :param content: QRadar Alert
    :type content: dict
    :return: Thehive alert
    :rtype: thehive4py.models Alerts
    """
    
    category_tags = []
    
    case_tags = ["src:QRadar"]
    for category in content.get("categories"):
        category_tags.append("Category={}".format(category))
    case_tags = add_tags(case_tags, category_tags)
    case_tags = add_tags(case_tags, [
        "Source={}".format(content.get("offense_source"))
    ])

    alert = Alert(title=content.get("description"),
                  tlp=2,
                  tags=case_tags,
                  severity=int(content.get('severity', "2")),
                  description=content.get('description'),
                  type='{} offense'.format(content.get('offense_type')),
                  source='QRadar',
                  caseTemplate=TheHive['template'],
                  sourceRef=str(content.get('id')),
                  artifacts=prepare_artifacts(content))

    logging.debug("Alert built for QRadar offense id {}".format(content.get('id')))
    return alert

def check_if_updated(current_a, new_a):
    for item in sorted(new_a):
        #Skip values that are not required for the compare
        if item is "date":
            continue
        #Artifacts require special attention
        if item is "artifacts":
            #loop through the newly created alert array to extract the artifacts and add them so a separate variable
            for i in range(len(new_a[item])):
                vars_current_artifacts = current_a[item][i]
                vars_new_artifacts = vars(new_a[item][i])
                
                #For each artifact loop through the attributes to check for differences
                for attribute in vars_new_artifacts:
                    if vars_current_artifacts[attribute] != vars_new_artifacts[attribute]:
                        logging.debug("Change detected for %s, new value: %s" % (vars_current_artifacts,vars_new_artifacts[attribute]))
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
                        logging.debug("Change detected for %s, new value: %s" % (vars_current_tags,vars_new_tags[tag]))
                        return True
            continue
         
        #Match other items of the new alert to the current alert (string based)
        if str(current_a[item]) != str(new_a[item]):
            logging.debug("Change detected for %s, new value: %s" % (item,str(new_a[item])))
            return True
    return False
    
def create_th_alerts(config, alerts):
    """
    :param config: TheHive config
    :type config: dict
    :param alerts: List of alerts
    :type alerts: list
    :return: create TH alert
    """
    thapi = TheHiveApi(config.get('url', None),
                       config.get('key'),
                       config.get('password', None),
                       config.get('proxies'),
                       config.get('verify'))
    for alert in alerts:
        offense_query = {
            "_and": [
                { "source": "%s" % alert.source },
                { "sourceRef": "%s" % alert.sourceRef }
            ]
        }
        logging.debug("Checking if offense with offense id %s exists" % alert.sourceRef )
        response = thapi.find_alerts(query=offense_query)
        alert_found = response.json()
        if len(alert_found) > 0:
            if alert.sourceRef in alert_found[0]['sourceRef']:
                logging.debug('Found offense id %s in Hive alert(%s), checking for changes' % (alert.sourceRef,alert_found[0]['id']))
                if not check_if_updated(alert_found[0], vars(alert)):
                    logging.debug("No changes found for %s" % alert_found[0]['id'])
                    continue
                logging.debug("Found changes for %s, updating alert" % alert_found[0]['id'])
                response = thapi.update_alert(alert_found[0]['id'],alert=alert)
            else:
                logging.info("The search in The Hive found a match, but it did not match the sourceRef. Please check this alert manually")
                continue
        else:
            response = thapi.create_alert(alert)
        logging.debug('API TheHive - status code: {}'.format(
            response.status_code))
        if response.status_code > 299:
            logging.debug('API TheHive - raw error output: {}'.format(
                response.raw.read()))
        logging.debug('Posting alert %s' % __repr__(alert))