# QRadar The Hive Integrator

## Introduction
This script is used to automate integrations between The Hive and QRadar. It started out with a script to schedule offense synchronisation (which is now moved to Synapse and this feature is only used to trigger Synapse).
After a while a few features were added, such as scheduling recurring searches for IOC's within The Hive and generating some reports based on API or AQL data.

## Functions
- Trigger Synapse to start syncing offenses
- Create searches based on the reference sets filled by the QRadar analyzer
- Scan The Hive and set off the QRadar analyzer for observables that are in scope for recurring searches
- Generate reports based on
	- API data
	- AQL searches

##Configuration
The following settings are available for the script. 
QRadar:
	proxies: << Use this for any proxy url's required
		http:
		https:
    url: https://<ip/hostname>:<port> << QRadar url
    key: <key> << QRadar API key. This can be the same as the key for the analyzer
    verify: <True/False/pathtocert> << Defines whether or not certificate hostname validation is enabled. Provide a path to a CA file if you have a specific file with authorized CA's
    enabled_datatypes: << Allows you to enable/disable certain datatypes.
        - ip
        - domain
        - fqdn
        - url
        - hash
    search_limit : 1 << The amount of days it searches back in time
    search_timeout : 86400 << The maximum duration it may take to complete the search
    polling_interval : 10 << polling interval for the search status
    url_root_domain_field: <field> << Field names
    url_fqdn_field:<field>
    url_field: <field>
    mail_recipient_field: <field>
    mail_sender_field: <field>
    mail_send_qid: <qid>
    mail_receive_qid: <qid>
    hash_md5: <field>
    hash_sha1: <field>
    hash_sha256: <field>
TheHive:
    proxies: << Use this for any proxy url's required
      http: 
      https: 
    url: https://<ip/hostname> << The Hive url
    key: <key> << The Hive API key
    verify: <True/False/pathtocert> << Defines whether or not certificate hostname validation is enabled. Provide a path to a CA file if you have a specific file with authorized CA's
Synapse:
    proxies: << Use this for any proxy url's required
        http: 
        https: 
    url: http://<url>:<port> << Synapse url
    verify: <True/False/pathtocert> << Defines whether or not certificate hostname validation is enabled. Provide a path to a CA file if you have a specific file with authorized CA's

### Example crontab

Supported actions
*/5 *   * * *   qthi    python3 /opt/QTHI/QRadar-TheHive-integrator.py offenses
0 */4   * * *   qthi    python3 /opt/QTHI/QRadar-TheHive-integrator.py scheduled_rs_search
0 1     * * *   qthi    python3 /opt/QTHI/QRadar-TheHive-integrator.py scheduled_observable_search
5 1     * * 1   qthi python3 /opt/QTHI/QRadar-TheHive-integrator.py reports -r "lse" -c "all"
0 2     * * 1-5   qthi python3 /opt/QTHI/QRadar-TheHive-integrator.py reports -r "lse" -c "standard"
0 */4     * * 1-5   qthi python3 /opt/QTHI/QRadar-TheHive-integrator.py reports -r "lse" -c "critical"
5 2     * * 1-5   qthi python3 /opt/QTHI/QRadar-TheHive-integrator.py reports -r "respc"
10 2     * * 1-5   qthi python3 /opt/QTHI/QRadar-TheHive-integrator.py reports -r "apr"