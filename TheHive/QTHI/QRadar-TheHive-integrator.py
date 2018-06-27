#Rest van de scripts ook omzetten naar logging
import logging
import argparse
import sys
import os

from config import QRadar
from QRadar_Modules.Get_Offenses import QRadarApi
from TheHive_Modules.THAlerts import *

def run():
    """
        Download QRadar offenses and create a new alert in TheHive
    """

    def offenses(args):
    
        #Load QRadar class into qrapi with config as input
        qrapi = QRadarApi(QRadar)
        
        #Retrieve offenses from QRadar
        offenses = qrapi.get_offenses(args.offense)
        
        #Loop through offenses to build a list of The Hive Alerts
        th_alerts = []
        for offense in offenses.get("data"):
            th_alerts.append(prepare_alert(offense))
        #Post alerts to The Hive
        create_th_alerts(TheHive, th_alerts)

    #Retrieve input parameters
    parser = argparse.ArgumentParser(description="Retrieve QRadar \
                                     offenses and feed them to TheHive")
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
    parser_offense.set_defaults(func=offenses)

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
    args = parser.parse_args()

    #Allow debug logging
    if args.debug:
        logging.basicConfig(filename='{}/qthi.log'.format(
                                os.path.dirname(os.path.realpath(__file__))),
                            level='DEBUG', format='%(asctime)s\
                                                   %(levelname)s\
                                                   %(message)s')
    args.func(args)

if __name__ == '__main__':
    run()