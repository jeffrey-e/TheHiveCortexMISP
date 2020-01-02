#Rest van de scripts ook omzetten naar logging
import logging
from logging.handlers import RotatingFileHandler
import argparse
import sys
import os
import datetime
import yaml
from thehive4py.models import Alert
from QRadar_Modules.Api_Requests import QRadarRequests
from QRadar_Modules.Searches import QRadarScheduledSearches
from TheHive_Modules.THSearches import TheHiveScheduledSearches
from TheHive_Modules.THAlerts import TheHiveRequests
from Synapse_Modules.Api_Requests import SynapseRequests

# Load config
script_folder = os.path.dirname(os.path.realpath(__file__))
Config = yaml.safe_load(open('%s/config/config.yaml' % script_folder))
TheHive = Config['TheHive']
QRadar = Config['QRadar']
Synapse = Config['Synapse']
# Load config for reports
ReportConfig = yaml.safe_load(open('%s/config/report_config.yaml' % script_folder))

#Load classes for future use
synapse_requests = SynapseRequests(Synapse)
th_requests = TheHiveRequests(TheHive, ReportConfig)
qr_requests = QRadarRequests(QRadar, ReportConfig)

#Function to create a pid file. This ensure that the script will not be started twice performing the same function
def pid_file(function, pid_action):
    #Get process id from the script
    pid = str(os.getpid())
    
    #Provide a filepath for the pid file
    pidfile = '{}/qthi-{}.pid'.format(os.path.dirname(os.path.realpath(__file__)), function)
    
    #If action is start, check for an existing pid file.
    if pid_action == 'start':
        if os.path.isfile(pidfile):
            #Read pid from pidfile
            pidfilehandler = open(pidfile, 'r') 
            pidfilepid = pidfilehandler.read()
            pidfilehandler.close()
            
            if not pidfilepid:
                logger.warning("PID file is empty, removing pid file")
                os.unlink(pidfile)
            
            #Check if pid file is present. Check if process is running. If so, exit the script. Else remove the pid file and run the script
            try:
                #Send kill signal 0 to a process. This does not trigger an actual but does trigger the check to find the process. Which will tell us if the process is alive or not
                os.kill(int(pidfilepid), 0)
                logger.error("%s is already running, exiting" % pidfile)
                sys.exit()
            except OSError:
                logger.warning("%s is not running, removing pid file" % pidfile)
                os.unlink(pidfile)
                
                #Create alert that PID file was removed, investigation is most likely required
                #Build alert as object defined in TheHive4Py models. sourceRef is based on a day to limit the amount of errors given (temporary workaround)
                pid_alert = Alert(title="Investigation required at The Hive, pid file removed",
                              tlp=2,
                              tags=['system_error','pid_file'],
                              severity=int('2'),
                              description="Check the logs of The Hive QTHI and look for any errors",
                              type='system error',
                              source='QTHI',
                              caseTemplate='System Errors',
                              sourceRef="qthi-{}".format(str(datetime.datetime.now().strftime("%y%m%d"))))
                              
                th_requests.create_th_alerts(pid_alert, "default")
                
        #Else create the pid file
        open(pidfile, 'w').write(pid)
    #If action is stop remove the pid file
    if pid_action == 'stop':
        os.unlink(pidfile)

def offenses(args):
    #Create pid file
    pid_file('offenses', 'start')
    
    logger.info("Starting to sync offenses to The Hive")
    
    #Trigger Synapse to synchronize offenses from QRadar
    synapse_requests.synapse_request("get", "/qradar2alert", 200)
    #if not result:
    #    sys.exit(1)
    
    #Remove pid file
    pid_file('offenses', 'stop')
    

#reports function made more generic to accomodate more types of reports. Old version only serves log source error reports. 

def reports(args): 
    #Create pid file
    pid_file('report', 'start')
    
    logger.info("Starting to generate reports for %s" % args.report)
    
    for report in args.report:
        #Selecting QRadar API report function from config file to run and getting report
        function = getattr(qr_requests, ReportConfig[report]['function'])
        #Retrieve report
        report_get = function(report, args.criticality[0])
        
        if report_get:
            #Build The Hive Alert
            th_alerts = []
            th_alerts.append(th_requests.prepare_alert(report_get, report))
            #Post alerts to The Hive
            th_requests.create_th_alerts(th_alerts, report)
        else:
            logger.info('Report "%s" had no results and is configured not to send a report when empty' % ReportConfig[report]['description'])
            continue
    #Remove pid file
    pid_file('report', 'stop')
        
def scheduled_rs_search(args):
    #Create pid file
    pid_file('scheduled_rs_search', 'start')
    
    logger.info("Starting to build searches based on reference sets")
    #Load QRadar class into qr_scheduled_rs_search and perform search
    qr_scheduled_rs_search = QRadarScheduledSearches(QRadar)
    qr_scheduled_rs_search.rs_search()
    
    #Remove pid file
    pid_file('scheduled_rs_search', 'stop')

def scheduled_observable_search(args):
    #Create pid file
    pid_file('scheduled_observable_search', 'start')
    
    logger.info("Starting to perform scheduled observable search")
    #Load QRadar class into qr_scheduled_observable_search and perform search
    qr_scheduled_observable_search = TheHiveScheduledSearches(TheHive, QRadar)
    qr_scheduled_observable_search.observable_search()
    
    #Remove pid file
    pid_file('scheduled_observable_search', 'stop')

def run():
    """
        Download QRadar offenses and create a new alert in TheHive
        Periodically perform searches within QRadar
    """ 
        
if __name__ == '__main__':
    run()
    
    #Provide a list of supported datatypes to use when retrieving observables from The Hive
    qr_supported_datatypes = ["ip","domain","fqdn","url","mail","hash"]
    qr_enabled_datatypes = QRadar['enabled_datatypes']
    
    #Check if the enabled datatypes are present in supported datatypes. If not, exit...
    for datatype in qr_enabled_datatypes:
        if not datatype in qr_supported_datatypes:
            datatype_not_supported = '{} is an unsupported datatype. Please check the configuration'.format(datatype)
            logging.error(datatype_not_supported)
            sys.exit()
    ''' CHANGE '''
    #Retrieve input parameters
    parser = argparse.ArgumentParser(description="Retrieve QRadar offenses and feed them to TheHive, or perform searches in QRadar for the Reference Sets required by the QRadarSearch analyzer")
    parser.add_argument("-d", "--debug",
                        action='store_true',
                        default=False,
                        help="generate a log file and active \
                              debug logging")
    subparsers = parser.add_subparsers(help="subcommand help")
    parser_offense = subparsers.add_parser('offenses', help="fetch offenses")
    parser_offense.add_argument("-o", "--offense",
                              metavar="ID",
                              action='store',
                              type=int,
                              nargs='+',
                              help="get QRadar offenses by offense ID",
                              required=False)
    parser_reports = subparsers.add_parser('reports', help="Run reports")
    ''' CHANGE - added apr and respc type, made arguments dynamic depending on report_config file'''
    parser_reports.add_argument("-r" ,"--report",
                              metavar="ID",
                              action='store',
                              type=str,
                              nargs='+',
                              #Using report config keys as arguments
                              choices = list(ReportConfig.keys()),
                              help="Specify a specific report.",
                              required=True
                              )
    ''' CHANGE - changed required to False'''
    parser_reports.add_argument("-c", "--criticality",
                              metavar="ID",
                              action='store',
                              type=str,
                              nargs='+',
                              help="Specify criticality:  \"critical\" or \"standard\". Default: \"all\"",
                              choices = ["all", "critical", "standard"],
                              default = ["all"],
                              required=False)
    parser_reports.set_defaults(func=reports)
    parser_scheduled_rs_search = subparsers.add_parser('scheduled_rs_search', help="Perform Reference Set Searches")
    parser_scheduled_rs_search.set_defaults(func=scheduled_rs_search)
    parser_scheduled_observable_search = subparsers.add_parser('scheduled_observable_search', help="Perform IOC matching against RS search results")
    parser_scheduled_observable_search.set_defaults(func=scheduled_observable_search)
    parser_offense.set_defaults(func=offenses)
    

    #Check if there were any args given. Else print help and exit
    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
    args = parser.parse_args()

    #Create main logger                                               # %(message)s')
    logger = logging.getLogger("QTHI")
    #Add File rotation
    handler = RotatingFileHandler('{}/logs/qthi.log'.format(os.path.dirname(os.path.realpath(__file__))), maxBytes=20000000, backupCount=10)
    logger.addHandler(handler)
    
    #Define the log format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #Add format to the handler
    handler.setFormatter(formatter)
    
    #Define the amount of logging to be written
    if args.debug:
        handler.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)
        
    args.func(args)

if __name__ == '__main__':
    run()
