# QRadar The Hive Integrator
NOTE: This is a development build and may contain unexpected behaviour, use this at your own risk!
If you are running QRadar, you can use this Integrator to integrate QRadar with The Hive.
The following features are currently available:
- Adds offenses to The Hive as Alert with the following information
    - Offense ID
    - Offense description
    - Offense Type
    - Related source and destination addresses as observables
    - Basic tagging
- Updates Alerts when the case is updated

# Usage
To use this Integrator you can 
- Place it on a server that can reach the API of both The Hive and QRadar
- If necessary, you can/need to patch the embedded Hive4Py module (See https://github.com/TheHive-Project/TheHive4py)
- Install any missing Python modules (don't have a list yet sorry \0/)
- Create a Case Template in The Hive
- Fill in the config.py for the required connection parameters
- Schedule the script in crontab or something similar

# To Do
- Clean up code
- Add module requirements

If you have any questions, I try to be active at The Hive's Gitter room (https://gitter.im/TheHive-Project/TheHive)
