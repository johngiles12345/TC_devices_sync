import requests
import json
import sys
import os
import csv
import time
import string
import re
from datetime import date, datetime
from cryptography.fernet import Fernet
import logging
import numpy as np
import pandas as pd
import pprint
import argparse
import cmath
import ast


"""This program reads in a credentials file and uses that info to connect to a NetScout nGeniusONE server and authenticate.
Then it looks for a CSV file with "current" as part of its name in the local directory.
If the 'current' CSV file is found, it will read that file into a pandas dataframe for comparison later.
Also, if it finds one, it will rename the file to create a backup copy in the local directory with "archive" in the name.
Then it makes an API request to get the configuration attributes for the requested config as they exist "right now" in the system.
Then it takes that "right now" config data in json format and translates it into a pandas dataframe that
 matches the schema of the "current" dataframe.
If it doesn't find a "current" CSV files (firt time run), it will use the config settings it reads from nG1 server and
 will create a "current" CSV file.
Then it writes this "right now" dataframe out to a date-time stamped CSV file that replaces the "Current" CSV file.
Then the program compares the "current" dataframe to the "right now" dataframe to see if there are any changes.
If there are added configuration elements, deleted elements or modified elements, this information will be written to "diff" CSV file.
The operator can examine the "diff" CSV file to understand what has changed since the last time this program ran.
Note: To connect to an nG1 server, you must first run the script cred_script_nG1.py. This is a menu-driven,
 interactive program that can run in a DOS command console or a MAC/Linux console.
After running that script, the ng1_config_sync.py can be run without any human interaction.
The user must specify which type of config they want (sites, client_comm, interfaces or apps).
They do this by including an argument when they run the program. Example; ./ng1_config_sync --config sites.
The example assumes they are running the binary version of this program and not the .py version.See below.
They can also specify a "--set" flag that tells the program to also write any config differences found to the nG1 API.
Note: For the case where you are running on a Linux server that does not have access to the internet, or you
 don't need the source code, there are binary versions of both programs in this repo that allow you to run
 it like a bash script (./), The version of python used, the python program, modules and all libraries needed
 are wrapped in. No dependencies needed. Just upload the binaries, chmod 777 to both filenames and run with ./
Any runtime info or errors are written to a date-time stamped log file created in the local directory.
This program was written by John Giles, NetScout SE. Initial version 0.1 created January 2021.
"""

# Disable the warnings for ignoring Self-Signed Certificates
requests.packages.urllib3.disable_warnings()

class Credentials:
    """
        A class to hold nG1 user credentials and other nG1 connection criteria.
        This is needed to create an API connection to nG1 and authenticate to nG1.
        The single API connection can be resued based on a session cookie that we will obtain later.
        The authentication is the same as logging into nG1 with username:password or by a token.
        The token can be created by the nG1 admin. Within the User Configuration for a specific user,
         the admin can click on "generate token" to create a token that takes the place of username:password.
        This token can be entered when running the cred_script_nG1 program.
        ...
        Attributes
        ----------
        ng1hostname : str
            The hostname of the ng1 server.
        ng1port : str
            The port to use for the HTTP-HTTPS connection.
        ng1username : str
            The ng1 username for the connection.
        ng1password : str
            The encrypted ng1 password if using a password.
        ng1password_pl: str
            The unencrypted password for the connection.
        use_token : bool
            Use a token rather than a password for the connection.
        ng1token : str
            The encrypted token if using a token.
        ng1token_pl: str
            The decrypted ng1 token if using a token.
        ng1key : str
            The key contents of the private ng1key_file.
        expiry_time : str
            The number of seconds before the encrypted password or token expires.
        """
    def __init__(self):
        self.ng1hostname = ''
        self.ng1port = ''
        self.ng1username = ''
        self.ng1password = ''
        self.ng1password_pl = ''
        self.use_token = False
        self.ng1token = ''
        self.ng1token_pl = ''
        self.ng1key_file = ''
        self.pkey = ''
        self.expiry_time = ''

class ApiSession:
    """
        A class to hold the parameters needed to exchange API data over a persistent API session.
        ...
        Attributes
        ----------
        ng1_host : str
            A combination of the web protocol (HTTP or HTTPS) + nG1 Hostname (DNS or IP addr) + the
             protocol port (80, 8080, 443, 8443).
        headers : str
            The HTTP header info. We use this to tell the nG1 API that we would like it to return data
             in the JSON format.
        cookies : str
            The HTTP session cookie that nG1 returns upon establishing the initial API session. This
             cookie will be used with every subsequent API call until we are finished. This tells the
             nG1 to autheticate each API call without establishing a brand new API session. This is much
             faster than creating and destroying an API session for each and every API we make. When we
             are all done, we will gracefully close the API session and release it from nG1.
        credentials : str
            The combination of username:password if using a password, if using a token, this is set to 'Null'.
        """
    def __init__(self):
        self.ng1host = ''
        self.header = ''
        self.cookies = ''
        self.credentials = ''

def flags_and_arguments(prog_version, logger):
    """Allows the user to input a mandatory argument of --config to specify which nG1 configuration they want to modify.
    Also allows the user to add optional flags to the launch command.
    Adding to --set flag will tell the program to both get the nG1 config and set the nG1 config to
     match the "current" config file.
    If the --set flag is not specified by the user, the program will gather the current nG1 config and compare it
     to the "current" config file. It will produce the config differences "change log" file and exit without
     doing any set commands to nG1 (will not sync the current file to the actual nG1 configuration).
    The --config argument is mandatory. This program can sync different types of nG1 configurations.
     So the user must specify which type of configuration they want to get or sync to.
    :program_version: Pass in the program version so the user can type --version.
    :logger: An instance of the logger class so we can write error messages if they occur.
    """
    try:
        # Define the program description
        text = 'This program is used to configure nGeniusONE either mannually or programmatically.'
        # Initiate the parser with a description
        parser = argparse.ArgumentParser(description=text)
        parser.add_argument('--set', action="store_true", help='set the nGeniusONE config to match the xxxx_config_current.csv', dest='set', default=False)
        parser.add_argument('--version', action="store_true", help="show program version and exit", dest='version', default=False)
        parser.add_argument('--config', dest='config_type', required=True, action="store", choices=['sites', 'client_comm', 'interfaces', 'apps'],
                    help="specify which nGeniusONE configuration you want; sites, client_comm, interfaces or apps")
        # Parse the arguments and create a result.
        args = parser.parse_args()
        config_type = args.config_type
        if args.version == True: # They typed either "-V" or "--version" flags.
            print(f'Program version is: {prog_version}')
            sys.exit()
        if args.set == True: # They typed the "--set" flag.
            is_set_config_true = True # I need to do a get and a set operation.
        else:
            is_set_config_true = False # I only need to do a get operation.
        status = True

        return status, is_set_config_true, config_type
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] Parsing the arguments has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        is_set_config_true = False
        config_type = ''

        return status, is_set_config_true, config_type

def create_logging_function(config_type):
    """Creates the logging function and specifies a log file to write to that is date-time stamped.
    :config_type: The type of configuration argument that the user specified when they launched the program.
    :return: The logger instance if successfully completed, and the logging filename. Return False if not successful.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    log_filename = 'nG1_config_sync_' + config_type + '_' + date_time + '.log' #The name of the log file we will write to.

    try:
        # Call the basicConfig module and pass in the log file filename.
        logging.basicConfig(filename=log_filename, format='%(asctime)s %(message)s', filemode='a+')
        # Call the logging class and create a logger object.
        logger = logging.getLogger()
        # Set the logging level to the lowest setting so that all logging messages get logged.
        logger.setLevel(logging.INFO) # Allowable options include DEBUG, INFO, WARNING, ERROR, and CRITICAL.
        # Write the current date and time to the log file to at least show when the program was executed.
        logger.info(f"*** Start of logs {date_time} ***")
        return logger, log_filename
    except:
        return False

def get_decrypted_credentials(cred_filename, ng1key_file, logger):
    """Read in the encrypted user or user-token credentials from a local CredFile.ini file.
    Decrypt the credentials and place all the user credentials attributes into a creds instance.
    :cred_filename: A string that is the name of the cred_filename to read in.
    :ng1key_file: A string that is the name of the ng1's key file to read in.
    :return: If successful, return the creds as a class instance that contains all the params needed to
     connect to the ng1 server via HTTP or HTTPS and authenticate the user. 
    :logger: An instance of the logger class so we can write error messages if they occur.
    Return False if any error occurrs.
    """
    # Create a creds instance to hold our user credentials.
    creds = Credentials()
    # Retrieve the decrypted credentials that we will use to open a session to the ng1 server.
    try:
        try: # Open the keyfile containing the key needed to decrypt the password.
            with open(ng1key_file, 'r') as ng1key_in:
                ng1key = ng1key_in.read().encode() # Read the key as a string.
                fng1 = Fernet(ng1key) # Create an instance of the Fernet class to hold the key info.
        except IOError as e: # Handle file I/O errors.
            print(f"\n[ERROR] Fatal error: Unable to open ng1key file: {ng1key_file}")
            print('Did you run the cred_script_nG1.py first?')
            logger.critical(f"[ERROR] Fatal error: Unable to open ng1key file: {ng1key_file}")
            logger.error(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
        except Exception as e:
            logger.exception(f"[ERROR] Fatal error: Unable to open ng1key_file: {ng1key_file}")
            logger.exception(f"Exception error is:\n{e}")
            return False
        with open(cred_filename, 'r') as cred_in:
            lines = cred_in.readlines()
            creds.ng1token = lines[4].partition('=')[2].rstrip("\n")
            #Check to see if we are expected to use an API Token or Username:Password
            # print(f' creds.ng1token is: {creds.ng1token}')
            if len(creds.ng1token) > 1: # Yes use a Token rather than a password.
                creds.use_token = True
                creds.ng1token_pl = fng1.decrypt(creds.ng1token.encode()).decode() # Use the key to decrypt.
                creds.ng1username = lines[2].partition('=')[2].rstrip("\n")
            else:
                creds.use_token = False # No, do not use a Token, but rather use a password.
                creds.ng1username = lines[2].partition('=')[2].rstrip("\n")
                creds.ng1password = lines[3].partition('=')[2].rstrip("\n")
                creds.ng1password_pl = fng1.decrypt(creds.ng1password.encode()).decode() # Use the key to decrypt.
            creds.ng1hostname = lines[1].partition('=')[2].rstrip("\n")
            creds.ng1Port = lines[5].partition('=')[2].rstrip("\n")
    except IOError as e: # Handle file I/O errors.
        logger.error(f"[ERROR] Fatal error: Unable to open cred_filename: {cred_filename}")
        logger.error(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
        return False
    except Exception as e: # Handle other unexpected errors.
        logger.exception(f"[ERROR] Fatal error: Unable to open cred_filename: {cred_filename}")
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

    return creds # The function was successful.

def determine_ng1_api_params(creds, logger):
    """Based on the values in the creds instance, determine what all the nG1 API connection and authentication parameters are.
    :creds: A class instance that holds all our nG1 connection and user authentication credentials values.
    :logger: An instance of the logger class so we can write error messages if they occur.
    :return: If successful, return the nG1 API parameters for ng1_host, headers, cookies and credentials.
    Return False if any error occurrs.
    """
    # You can use an authentication token named NSSESSIONID obtained from the User Management module in nGeniusONE (open the user and click Generate New Key).
    # This token can be passed to nG1 as a cookie so that we can autheticate.
    # If we are using the token rather than credentials, we will set credentials to 'Null'.
    # If we are using the username:password rather than a token, we will set cookies to 'Null'.
    # Initialize the return parameters just in case we have an error and need to return False.

    # Create an ApiSession instance to hold our API Session parameters. Use these params for all subsequent API calls.
    session = ApiSession()

    try:
        if creds.use_token == True: # The user had selected token rather than username:password.
            session.credentials = 'Null' # Set username:password to 'Null'. We won't be using these.
            session.cookies = {'NSSESSIONID': creds.ng1token_pl} # In this case we will use the token read from the CredFile.ini file.
        # Otherwise set the credentials to username:password and use that instead of an API token to authenticate to nG1.
        else: # The user had selected username:password rather than a token.
            session.cookies = 'Null' # Set cookies to 'Null'. We won't be using a token. We will use username:password instead.
            session.credentials = creds.ng1username + ':' + creds.ng1password_pl # Combines the username and the decrypted password.

        # set the URL web protocol to match what was read out of the CredFile.ini file for ng1Port.
        if creds.ng1Port == '80' or creds.ng1Port == '8080':
            web_protocol = 'http://'
        elif creds.ng1Port == '443' or creds.ng1Port == '8443':
            web_protocol = 'https://'
        else: # Not a standard port, so I don't know if I should use HTTP or HTTPS.
            print(f'[CRITICAL] nG1 destination port {creds.ng1Port} is not equal to 80, 8080, 443 or 8443')
            logger.critical(f'[CRITICAL] nG1 destination port {creds.ng1Port} is not equal to 80, 8080, 443 or 8443')
            status = False
            return status, session # As we are returning multiple params, we will status to set True or False.
        # Build up the base URL to use for all nG1 API calls.
        session.ng1_host = web_protocol + creds.ng1hostname + ':' + creds.ng1Port

        # Hardcoding the HTTP header to use in all the nG1 API calls.
        # Specifies the JSON data type as the format of the data we want returned by the nG1 API.
        session.headers = {
            'Cache-Control': "no-cache",
            'Accept': "application/json",
            'Content-Type': "application/json"
        }
    except Exception as e:
        logger.exception(f"[ERROR] Fatal error: Unable to create log file function for: {log_filename}")
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        return status, session # As we are returning multiple params, we will status to set True or False.

    status = True # Success
    return status, session # As we are returning multiple params, we will status to set True or False.

def open_session(session, logger):
    """Open an HTTP or HTTPS API session to the nG1. Reuse that session for all commands until finished.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: True if successful. Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/rest-sessions" # The uri to use for nG1 API initial connection.
    url = session.ng1_host + uri

    # Perform the HTTP or HTTPS API call to open the session with nG1 and return a session cookie.
    try:
        if session.credentials == 'Null': # Use a token rather than username:password.
            # Null credentials tells us to use the token. We will use this post and pass in the cookies as the token.
            post = requests.request("POST", url, headers=session.headers, verify=False, cookies=session.cookies)
        elif session.cookies == 'Null': # Use a username:password credentials combo instead of a token.
            #split the credentials string into two parts; username and the unencrypted password.
            ng1username = session.credentials.split(':')[0]
            ng1password_pl = session.credentials.split(':')[1]
            # Null cookies tells us to use the credentials string. We will use this post and pass in the credentials string.
            post = requests.request("POST", url, headers=session.headers, verify=False, auth=(ng1username, ng1password_pl))
        else:
            # print(f'[CRITICAL] opening session to URL: {url} failed')
            logger.critical(f'[CRITICAL] opening session to URL: {url} failed.')
            # print('Unable to determine authentication by credentials or token')
            logger.critical('[CRITICAL] Unable to determine authentication by credentials or token.')
            return False
        if post.status_code == 200: # The nG1 API call was successful.
            print(f'[INFO] Opened Session to URL: {url} Successfully')
            logger.info(f'[INFO] Opened Session to URL: {url} Successfully')
            # Utilize the returned cookie for future authentication. Keep this session open for all nG1 API calls.
            session.cookies = post.cookies # Set the session.cookies param to equal the Web RequestsCookieJar value.
            return True # Success!
        else: # We reached the nG1, but the request has failed. A different HTTP code other than 200 was returned.
            logger.critical(f'[CRITICAL] opening session to URL: {url} failed. Response Code: {post.status_code}. Response Body: {post.text}.')
            return False
    except Exception as e: # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.critical(f'[CRITICAL] Opening the nG1 API session has failed')
        logger.critical(f'[CRITICAL] Cannot reach URL: {url}')
        logger.critical(f'[CRITICAL] Check the VPN or internet connection')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

def close_session(session, logger):
    """Close the HTTP or HTTPS API session to the nG1.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    try:
        uri = "/ng1api/rest-sessions/close"
        url = session.ng1_host + uri
        # perform the HTTPS API call
        close = requests.request("POST", url, headers=session.headers, verify=False, cookies=session.cookies)

        if close.status_code == 200: # The nG1 API call was successful.
            print('[INFO] Closed nG1 API Session Successfully')
            logger.info('[INFO] Closed nG1 API Session Successfully')
            return True # Success! We closed the API session.
        else: # The nG1 API call failed.
            logger.error(f'[ERROR] closing session failed. Response Code: {close.status_code}. Response Body: {close.text}.')
            return False
    except Exception as e:
        # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.error(f'[CRITICAL] Closing the nG1 API session has failed')
        logger.exception(f"Exception error is:\n{e}")
        print('[CRITICAL] Closing the nG1 API session has failed')
        print('We did not reach the nG1. Check your VPN or internect connection')
        return False

def write_device_interfaces_config_to_csv(devices_dict, logger):
    """Write the device and interface data to a CSV file using a json dictionary.
    :devices_dict: The dictionary of device + device interface data collected.
    :logger: An instance of the logger object to write to in case of an error.
    :return: True if successful. Return False if there are any errors or exceptions.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    filename = 'nG1_get_all_interfaces_' + str(date_time) + '.csv' # Assemble the CSV filename string.
    try:
        with open(filename,'w', encoding='utf-8', newline='') as f:
            fieldnames = ['Infinistream', 'interfaceName', 'alias', 'interfaceNumber', 'portSpeed', 'interfaceSpeed', 'status', 'alarmTemplateName', 'virtulization', 'activeInterfaces', 'inactiveInterfaces', 'interfaceLinkType', 'nBAnASMonitoring']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            # Write the first row as a header that includes names for each column as specified by fieldnames above.
            writer.writeheader()
            for device in devices_dict:
                # Pull the list of interfaces out of the devices dictionary for the device we are looping on now.
                interfaces_list = devices_dict[device]
                # Write each interface for this one device as a row in the CSV file.
                for interface in interfaces_list:
                    # Add the name of the Infinistream to this row.
                    interface['Infinistream'] = device
                    writer.writerow(interface)
            print(f'[INFO] Writing Device Interfaces to CSV file: {filename} was Successful')
            logger.info(f'[INFO] Writing Device Interfaces to CSV file: {filename} was Successful')
            return True # Success!
    except IOError as e:
        logger.error(f'[ERROR] Unable to write Interface Locations to the CSV file: {filename}')
        logger.error(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
        return False
    except Exception as e: # Handle other exceptions such as attribute errors.
        logger.error(f'[ERROR] Unable to write Interface Locations to the CSV file: {filename}')
        logger.exception(f"Exception error is:\n{e}")
        return False

def convert_json_dict_to_dataframe(config_data, config_type, logger):
    """Convert a nested python dictionary into a pandas dataframe.
    :config_data: The dictionary that holds the configuration data we extracted from nG1.
    :config_type: The type of config data to get (sites, client_comm, interfaces, apps)
    :logger: An instance of the logger object to write to in case of an error.
    :return: Return status = True and the "right now" pandas dataframe if successful.
    Return status = False and an empty dataframe if there are any errors or exceptions.
    """
    if config_type == 'sites':
        column_headers = ['id','name', 'addresses', 'speedKbps']
    elif config_type == 'client_comm':
        column_headers = ['CHANGE ME']
    #elif config_type == 'interfaces':
        # interate_column = 'CHANGE ME' # Use this column to determine if rows were added or removed.
        # column_headers = ['CHANGE ME']
    elif config_type == 'apps':
        column_headers = ['CHANGE ME']
    else:
        print('[ERROR] Unable to convert JSON config data to a dataframe')
        logger.info(f'[ERROR] Unable to set differences, config type {config_type} is invalid')
        return False
    try:
        # Initialize an empty list to hold the per-interface data.
        rows = []
        status = True # Tells the calling function if we were successful in the conversion.
        for key in config_data: # Iterate through each key in the dictionary.
            config_items_rows = config_data[key] # Pull out the list of configs from the parent key.
            for item in config_items_rows: # Iterate through each config item as they will be the rows in our dataframe.
                rows.append(item) # Appending the config item row to the 'rows' list to produce a flat dataset.
        # Put the flat list of config items rows into a pandas dataframe.
        df_right_now = pd.DataFrame(rows)
        df_right_now = df_right_now[column_headers] # reorder the columns.

        # Pandas dataframes don't have types of 'list' or 'dict', so we need to convert any of these to strings.
        if config_type == 'sites': # One of the sites columns includes lists. We cannot include lists or dicts in a dataframe.
            df_right_now['addresses'] = df_right_now.addresses.astype('str') # Cast the list of ipaddress ranges into a string.

        return status, df_right_now # You can't have a whole dataframe be either True or False. So we add a status boolean.
    except Exception as e:
        logger.exception(f'[ERROR] Conversion of JSON config data to dataframe has failed')
        logger.exception(f"Exception error is:\n{e}")
        status = False
        df_right_now = ''
        return status, df_right_now

def write_dataframe_to_csv(df, csv_filename, logger):
    """Write the device and interface dataframe to a CSV file.
    :df: The dataframe of nG1 config data collected.
    :csv_filename: The name of the CSV file to write to.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    try:
        df.to_csv(csv_filename, header=True, encoding='utf-8', index=False) # Write the dataframe to the CSV file.
    except PermissionError as e:
        logger.error(f'[ERROR] Permission Error: Write dataframe to CSV file: {csv_filename}')
        logger.error(f'[ERROR] Permission Error({e.errno}):  {e.strerror}.')
        print(f'[ERROR] Conversion of CSV file: {csv_filename} to a dataframe has failed')
        print('Do you have the file open?')
        status = False
        config_current_is_found = False
        current_df = ''
        return status, config_current_is_found, current_df
    except IOError as e: # Handle file I/O errors.
        print(f'\n[ERROR] I/O error: Write dataframe to CSV file: {csv_filename}')
        logger.error(f'[ERROR] I/O Error: Write dataframe to CSV file: {csv_filename}')
        logger.error(f'[ERROR] I/O Error({e.errno}):  {e.strerror}.')
    except Exception as e:
        logger.exception(f'[ERROR] Write dataframe to CSV file: {csv_filename} has failed"')
        logger.exception(f'[ERROR] Exception error is:\n{e}')
        return False

    return True

def backup_current_CSV(config_current_csv, config_archive_csv, config_type, logger):
    """If this program has run before, there will be a "current" copy of the configuration CSV File.
    If found in the local directory, read it into a pandas dataframe for comparison later.
    If found in the local directory, rename it to "archive" with a time-date stamp.
    :config_current_csv: A string. The CSV filename of the current config created at the last run of this program.
    :config_archive_csv: A string. The CSV filename of the backup we will create if a "current" csv file exists.
    :config_type: The type of config data to get (sites, client_comm, interfaces, apps)
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True and the current pandas dataframe.
    Return config_current_is_found = True is the "current" CSV file is found, or False if the file is not found.
    Return status = False and an empty pandas dataframe if there are any errors or exceptions.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    try:
        # if config_current_csv exists read in as a pandas df, rename and cp current to archive then return the current df.
        if os.path.isfile(config_current_csv):
            current_df = pd.read_csv(config_current_csv)
            #print(f'\nCurrent df is: \n{current_df}')
            #print(f'dtypes are: \n{current_df.dtypes}')
            if config_type == 'sites':
                # Pandas dataframes don't have types of 'list' or 'dict', so we need to convert any of these to strings.
                current_df['addresses'] = current_df.addresses.astype('str') # Cast the list of ipaddress ranges into a string.
            config_archive_csv = config_archive_csv + '_' + str(date_time) + '.csv'
            current_df = current_df[['id','name', 'addresses', 'speedKbps']] # reorder the columns.
            os.rename(config_current_csv, config_archive_csv) # rename the current CSV file to a time-date stamped archive CSV file.
            print(f"[INFO] Backing up file {config_current_csv} to {config_archive_csv} Successful")
            logger.info(f"[INFO] Backing up file {config_current_csv} to {config_archive_csv} Successful")
            config_current_is_found = True
            status = True
            # The current dataframe may contain new rows where the id number is blank as new config items don't have an id yet.
            current_df['id'] = current_df['id'].fillna(0) # Replace NaNs (empty id numbers) with zeros.
            return status, config_current_is_found, current_df
        else: # We did not find the config_current_csv file. We will create one based on what is set in nG1 currently.
            config_current_is_found = False
            status = True # This is not an error, return True. It is not required that this file exists.
            current_df = ''
            return status, config_current_is_found, current_df
    except PermissionError as e:
        logger.error(f'[ERROR] Conversion of CSV file: {config_current_csv} to a dataframe has failed')
        logger.error (f"[ERROR] Permission error is:\n{e}")
        print(f'[ERROR] Conversion of CSV file: {config_current_csv} to a dataframe has failed')
        print('Do you have the file open?')
        status = False
        config_current_is_found = False
        current_df = ''
        return status, config_current_is_found, current_df
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] Conversion of config data to dataframe has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        config_current_is_found = False
        current_df = ''
        return status, config_current_is_found, current_df

def modifiedRows(dfLeft, dfRight, config_type, logger):
    """This function takes in two pandas dataframes and determines if there are any config items
     that have been modified since the last time this program was run. A new dataframe (dfModifiedRows)
      is created that includes all rows for all possible cases; NoChange, *Added, *Deleted or *Modified.
      A new column (_Change) is appended to the dataframe to indicate the type of change that occurred.
    :dfLeft: A pandas dataframe. The 'current' set of config data from the previous program execution.
    :dfRight: A pandas dataframe. The 'right now' set of config data from the nG1 API call we just made.
    :config_type: The type of config data to get (sites, client_comm, interfaces, apps)
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True and the dfModifiedRows pandas dataframe.
    Return status = False and an empty pandas dataframe if there are any errors or exceptions.
    """
    if config_type == 'sites':
        column_headers = ['id','name', 'addresses', 'speedKbps', '_Change']
    elif config_type == 'client_comm':
        column_headers = ['CHANGE ME']
    #elif config_type == 'interfaces':
        # interate_column = 'CHANGE ME' # Use this column to determine if rows were added or removed.
        # column_headers = ['CHANGE ME']
    elif config_type == 'apps':
        column_headers = ['CHANGE ME']
    else:
        print(f'[ERROR] Unable to set differences, config type {config_type} is invalid')
        logger.info(f'[ERROR] Unable to set differences, config type {config_type} is invalid')
        return False
    try:
        dfMerged = dfLeft.merge(dfRight, indicator=True, how='outer') # Compare the "current" dfright data to the "right now" dfleft data.
        print(f'dfMerged is: \n{dfMerged}')
        # Convert '_merge' indicator column into a situation specific descriptive column:
        # left_only / right_only indicates a change to a config setting if the id and name values match.
        # - Keep the left value.
        # both, indicates no change to this config setting since last time the program was ran.
        # left_only (no matching id, name) indicates a config setting was deleted.
        # right_only (no matching user id) indicates a config setting was added.
        grp_cols = ['name'] # Use these column to determine if any of the other columns are different.
        step1DF = dfMerged.groupby(grp_cols).filter(lambda x: x.id.count() > 1)[dfMerged.groupby(grp_cols).filter(lambda x: x.id.count() > 1)['_merge'] == 'left_only']
        step1DF['_merge'].astype('object') # convert from categorical back to object
        step1DF['_merge'] = '*Mod_Orig' # The value to use in the _merge column for the modified row (config setting) as it was in the "current CSV".
        step2DF = dfMerged.groupby(grp_cols).filter(lambda x: x.id.count() > 1)[dfMerged.groupby(grp_cols).filter(lambda x: x.id.count() > 1)['_merge'] == 'right_only']
        step2DF['_merge'].astype('object') # convert from categorical dtype back to object.
        step2DF['_merge'] = '*Mod_New' # The value to use in the _merge column for the modified row (config setting) as it is in the "right now" CSV.
        dfChanges_orig_new = pd.concat([step1DF, step2DF])
        print(f'dfChanges_orig_new is \n{dfChanges_orig_new}')
        describers = {'_merge':{'both': 'No_Change', 'left_only':'*Deleted', 'right_only':'*Added'}} # The list of values we want to use in the _merge column.
        step3DF = dfMerged.groupby(grp_cols).filter(lambda x: x.id.count() == 1).replace(describers) # Replace the values in the _merge column.
        print(f'step3DF is \n{step3DF}')
        dfModifiedRows = pd.concat([dfChanges_orig_new, step3DF]) # Put the changes dataframe together with the added-deleted-nochange dataframe.
        dfModifiedRows.rename(columns={'_merge': '_Change'}, inplace=True) # Change the column name to '_Change' for readability.
        dfModifiedRows.sort_index(inplace=True) # Sort the dataframe so that differences appear at the bottom.
        dfModifiedRows = dfModifiedRows[['id','name', 'addresses', 'speedKbps', '_Change']] # Not sure if I need this rename columns step???
        print(f"\ndfModifiedRows after sort and rename index is: \n{dfModifiedRows}")
        status = True
        return status, dfModifiedRows
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] The check for modified config items has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        dfModifiedRows = ''
        return status, dfModifiedRows

def get_config_data_differences(current_df, right_now_df, config_type, logger):
    """This function takes in two pandas dataframes and determines if there are any config items
     that have been added, removed (deleted) or modified since the last time this program was run.
    :dfLeft: A pandas dataframe. The 'current' set of config data from the previous program execution.
    :dfRight: A pandas dataframe. The 'right now' set of config data from the nG1 API call we just made.
    :config_type: The type of config data to get (sites, client_comm, interfaces, apps)
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True and the diff_df pandas dataframe.
    Return status = False and an empty pandas dataframe if there are any errors or exceptions.
    """
    diff_df = ''
    try:
        status, dfModifiedRows = modifiedRows(right_now_df, current_df, config_type, logger)
        if status == False: # Determining the modified config items has failed.
            did_anything_change = False
            diff_df = ''
            return status, did_anything_change, diff_df
        did_anything_change = dfModifiedRows._Change.isin(['*Mod_Orig', '*Mod_new', '*Added', '*Deleted']).any().any()
        if did_anything_change == False:
            print(f'[INFO] No differences found between the {config_type} current CSV and what is configured in nG1 ')
            logger.info(f'[INFO] No differences found between the {config_type} current CSV and what is configured in nG1')
            diff_df = ''
            status = True
            return status, did_anything_change, diff_df # Success. Return the status as True (no errors) and an empty diff_df dataframe.
        else:
            print(f'[INFO] Differences have been found between the {config_type} current CSV and what is configured in nG1')
            print(f'[INFO] Please review the {config_type}_change_log CSV file')
            logger.info(f'[INFO] Differences have been found between the {config_type} current CSV and what is configured in nG1')
            diff_df = dfModifiedRows
            status = True
            return status, did_anything_change, diff_df # Success. Return the status as True (no errors) and an empty diff_df dataframe.
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] The check for config differences between the current CSV file and what is configured in nG1 has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        did_anything_change = False
        diff_df = ''
        return status, did_anything_change, diff_df

def set_config_differences(session, diff_df, config_type, logger):
    """Use the nG1 API to set the configuration in the system for the config_type passed in.
    The goal is to make the nG1 configuration match what is contained in the "current" CSV file.
    This way the "current" CSV file can be modified by the user and this program can keep the
     configuration on nG1 in sync with what gets written to the "current" CSV file.
    :session: An instance of the ApiSession class that holds all our API session params.
    :diff_df: The pandas dataframe that holds the notation of differences found between the "current"
     CSV file and what is in the nG1 configuration "right now".
    :config_type: The type of config data to get (sites, client_comm, interfaces, apps)
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return the sites info in JSON format.
    Return False if there are any errors or exceptions.
    """
    # Depending on which config argument supplied, the nG1 API url will be different.
    if config_type == 'sites':
        uri = "/ng1api/ncm/sites/"
    elif config_type == 'client_comm':
        uri = "/ng1api/ncm/clientcommunities/"
    #if config_type == 'interfaces':
        #uri = "/ng1api/ncm/sites/" #NOTE: Put the mastercard functions in this program.
    elif config_type == 'apps':
        uri = "/ng1api/ncm/applications/"
    else:
        print(f'[ERROR] Unable to set differences, config type {config_type} is invalid')
        logger.info(f'[ERROR] Unable to set differences, config type {config_type} is invalid')
        return False
    url = session.ng1_host + uri

    dfAdded = diff_df.loc[diff_df['_Change'] == '*Added'] # Find the added rows (config items that were added).
    # print(f'dfAdded that should be empty is: \n{dfAdded}')
    if len(dfAdded.index) != 0: # We found added config items
        dfAdded = dfAdded.iloc[:,:-1] # Filter out the last column "_Changed", but include all rows and all other columns.
        dfAdded = dfAdded.iloc[:,1:] # Filter out the first column "id" as new config items don't have an id yet.
        if config_type == 'sites': # Set operations vary depending on what type of configuration was specified in the launch argument.
            config_data = {"sites": []} # Initialize an empty dictionary to hold site configs.
            dfAdded['associateAll']='true' # Hardcoding that all sites should be associated to all interfaces (MEs).
            config_items = dfAdded.to_dict('records') # Convert the dataframe for added configs to a python dictionay.
            i = 0
            for config_item in config_items: # Loop through the added config items and add them to the sites dictionary.
                #print(f'config_item is: \n{config_item}')
                addr_list = config_items[i]['addresses'] # There may be several added sites, so we need an index in our loop.
                addr_list = ast.literal_eval(addr_list) # We have to convert a string of addresses to a list of addresses.
                config_item['addresses'] = addr_list # Add the address list to the dictionary
                config_item['associateAll'] = True # Hardcoding that all sites should be associated to all interfaces (MEs).
                #print(f'config_item is: \n{config_item}')
                config_data["sites"].append(config_item) # This site config item is ready to be added to the dictionary.
                i += 1
            #print(f'config_data is: {config_data}')
        set_type = 'add'
        # Pass the dictionary to the function that actually configures items.
        status = set_config_items(session, config_type, config_data, set_type, logger)
        if status == False: # Adding configuration items has failed.
            print(f'[ERROR] Unable to add {config_type} config items to the nG1 API')
            logger.error(f'[ERROR] Unable to add {config_type} config items to the nG1 API')
            return False
    dfDeleted = diff_df.loc[diff_df['_Change'] == '*Deleted'] # Find the deleted rows (config items that were removed).
    if len(dfDeleted.index) != 0: # We found deleted config items
        dfDeleted = dfDeleted[['id']] # Filter out all columns except the id column (we only need ids to delete).
        dfDeleted.reset_index() # reset the dataframe index.
        print(f'\ndfDeleted is: \n{dfDeleted}')
        if config_type == 'sites':
            config_data = {"sites": []}
            config_items = dfDeleted.to_dict('records')
            i = 0
            for config_item in config_items: # Loop through the deleted config items and add them to the sites dictionary.
                #print(f'config_item is: \n{config_item}')
                config_data["sites"].append(config_item) # This site config item is ready to be added to the dictionary.
                i += 1
            print(f'config_data is: {config_data}')
        set_type = 'delete'
        status = set_config_items(session, config_type, config_data, set_type, logger)
        if status == False: # Deleting configuration items has failed.
            print(f'[ERROR] Unable to delete {config_type} config items to the nG1 API')
            logger.error(f'[ERROR] [ERROR] Unable to delete {config_type} config items to the nG1 API')
            return False
    #except Exception as e: # Handle other unexpected errors.
        #logger.exception(f'[ERROR] get {config_type} nG1 API request failed')
        #logger.exception(f'[ERROR] URL sent is: {url}')
        #logger.exception(f"[ERROR] Exception error is:\n{e}")
        #return False

    return True

def get_ng1_config(session, config_type, logger):
    """Use the nG1 API to get the configuration in the system for the config_type passed in.
    :config_type: The type of config data to get (sites, client_comm, interfaces, apps)
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return the sites info in JSON format.
    Return False if there are any errors or exceptions.
    """
    if config_type == 'sites':
        uri = "/ng1api/ncm/sites/"
    if config_type == 'client_comm':
        uri = "/ng1api/ncm/clientcommunities/"
    #if config_type == 'interfaces':
        #uri = "/ng1api/ncm/sites/" #NOTE: Put the mastercard functions in this program.
    if config_type == 'apps':
        uri = "/ng1api/ncm/applications/"
    url = session.ng1_host + uri
    try:
        # perform the HTTPS API call to get the sites information
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)

        if get.status_code == 200:
            # success
            print(f'[INFO] get {config_type} nG1 API request Successful')
            logger.info(f'[INFO] get {config_type} nG1 API request Successful')
            # return the json object that contains the site information
            return get.json()
        else:
            logger.error(f'[ERROR] get {config_type} nG1 API request failed. Response Code: {get.status_code}. Response Body: {get.text}.')
            return False
    except Exception as e: # Handle other unexpected errors.
        logger.exception(f'[ERROR] get {config_type} nG1 API request failed')
        logger.exception(f'[ERROR] URL sent is: {url}')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

def set_config_items(session, config_type, config_data, set_type, logger):
    """Use the nG1 API to add, delete or modify new configuration items in the system for the config_type and config_data passed in.
    :session: An instance of the ApiSession class that holds all our API session params.
    :config_type: The type of config data to get (sites, client_comm, interfaces, apps)
    :config_data: The configuration data dictionary that hold the config items we need to add.
    :set_type: The type of config operation to perform; add, delete, modify.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True.
    Return False if there are any errors or exceptions.
    """
    if config_type == 'sites':
        uri = "/ng1api/ncm/sites/"
    if config_type == 'client_comm':
        uri = "/ng1api/ncm/clientcommunities/"
    #if config_type == 'interfaces':
        #uri = "/ng1api/ncm/sites/" #NOTE: Put the mastercard functions in this program.
    if config_type == 'apps':
        uri = "/ng1api/ncm/applications/"
    url = session.ng1_host + uri
    try:
        # use json.dumps to provide a serialized json object (a string actually)
        # this json_string will become our new configuration as defined by what is in the config_data dictionary.
        json_string = json.dumps(config_data)
        #print(f'New {config_type} json_string is: {json_string}')

        # perform the nG1 API Post call with the serialized json object from config_data
        if set_type == 'add':
            # this will create the new site(s), client communities, interfaces, apps, etc. in nG1 for this config_data.
            post = requests.post(url, headers=session.headers, data=json_string, verify=False, cookies=session.cookies)

            if post.status_code == 200: # The create config items nG1 API call succeded.
                print(f'[INFO] The add {config_type} via nG1 API operation was Successful')
                logger.info(f'[INFO] The add {config_type} via nG1 API operation was Successful')
                return True
            else:
                print(f'[ERROR] The add {config_type} via nG1 API operation has failed')
                logger.error(f'[ERROR] The add {config_type} via nG1 API operation has failed. Response Code: {post.status_code}. Response Body: {post.text}.')
                return False
        elif set_type == 'delete':
            # this will remove the delted site(s), client communities, interfaces, apps, etc. in nG1 for this config_data.
            delete = requests.delete(url, headers=session.headers, data=json_string, verify=False, cookies=session.cookies)

            if delete.status_code == 200: # The create config items nG1 API call succeded.
                print(f'[INFO] The delete {config_type} via nG1 API operation was Successful')
                logger.info(f'[INFO] The delete {config_type} via nG1 API operation was Successful')
                return True
            else:
                print(f'[ERROR] The delete {config_type} via nG1 API operation has failed')
                logger.error(f'[ERROR] The deleted {config_type} via nG1 API operation has failed. Response Code: {delete.status_code}. Response Body: {delete.text}.')
                return False
        elif set_type == 'modify':
            # this will update the modified site(s), client communities, interfaces, apps, etc. in nG1 for this config_data.
            put = requests.put(url, headers=session.headers, data=json_string, verify=False, cookies=session.cookies)

            if put.status_code == 200: # The create config items nG1 API call succeded.
                print(f'[INFO] The modify {config_type} via nG1 API operation was Successful')
                logger.info(f'[INFO] The modify {config_type} via nG1 API operation was Successful')
                return True
            else:
                print(f'[ERROR] The modify {config_type} via nG1 API operation has failed')
                logger.error(f'[ERROR] The modify {config_type} via nG1 API operation has failed. Response Code: {put.status_code}. Response Body: {put.text}.')
                return False
        else:
            return False # I did not get any valid set_type.
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] The add {config_type} via nG1 API operation has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

# -----------------------------------------------------------------------------------------------------------------
def main():
    prog_version = '0.1'
    # Create a logger instance and write the starting date_time to a log file.
    logger, log_filename = create_logging_function(config_type)
    if logger == False: # Creating the logger instance has failed. Exit.
        print("\n[CRITICAL] Main, Creating the logger instance has failed")
        print('Exiting...')
        sys.exit()

    status, is_set_config_true, config_type = flags_and_arguments(prog_version, logger)
    if status == False: # Parsing the user entered flags or arguments has failed Exit.
        print("\n[CRITICAL] Main, Parsing the user entered flags or arguments has failed")
        print('Exiting...')
        sys.exit()

    # Hardcoding the name of the "current" CSV file that holds the config data from the last run.
    config_current_csv = config_type + '_config_current.csv' # This file will get overwritten by design if the same config_type is run again.
    # Hardcoding the name of the "archive" CSV file that we will use to backup the "current" CSV file.
    config_archive_csv = config_type + '_config_archive' # No extention as we will append a time-date + .csv to the name.
    # Hardcoding the name of the "change_log" CSV file that we will use to output and differences seen since last program execution.
    change_log_csv = config_type + '_change_log.csv' # This file will get overwritten by design if the same config_type is run again.

    # Hardcoding the filenames for encrypted credentials and the key file needed to decrypt the credentials.
    cred_filename = 'CredFile.ini'
    os_type = sys.platform
    if os_type == 'linux':
        ng1key_file = '.ng1key.key' # hide the probekey file if Linux.
    else:
        ng1key_file = 'ng1key.key' # don't hide it if Windows.

    # Get the user's credentials from a file and decrypt them.
    creds = get_decrypted_credentials(cred_filename, ng1key_file, logger)
    if creds == False: # Creating the creds instance has failed. Exit.
        logger.critical(f"[CRITICAL] Main, Getting the login credentials from file: {cred_filename} failed")
        print(f"\n[CRITICAL] Main, Getting the ng1 login credentials from file: {cred_filename} failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Based on what is in the creds, determine all the parameters needed to make an nG1 API connection.
    status, session = determine_ng1_api_params(creds, logger)
    if status == False: # Determining the nG1 API parameters has failed. Exit.
        logger.critical(f"[CRITICAL] Main, determining the nG1 API parameters has failed")
        print(f"\n[CRITICAL] Main, determining the nG1 API parameters has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Open an API session to nG1 and keep it open for all subsequent calls.
    status = open_session(session, logger)
    if status == False: # Opening the HTTP-HTTPS nG1 API session has failed. Exit.
        logger.critical(f"[CRITICAL] Main, opening the HTTP-HTTPS nG1 API session has failed")
        print(f"\n[CRITICAL] Main, opening the HTTP-HTTPS nG1 API session has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Backup the current configuration CSV created the last time this program ran (rename it if it exists).
    status, config_current_is_found, current_df = backup_current_CSV(config_current_csv, config_archive_csv, config_type, logger)
    if status == False: # Backing up the current CSV config file has failed.
        logger.critical(f"[CRITICAL] Main, backup_current_csv has failed")
        print(f"\n[CRITICAL] Main, backup_current_csv has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Get config info from the nG1 API. Returned as a python object (a json formatted dictionary).
    config_data = get_ng1_config(session, config_type, logger)
    if config_data == False: # Getting the config data from the nG1 API has failed. Exit.
        logger.critical(f"[CRITICAL] Main, getting the {config_type} data from the nG1 API has failed")
        print(f"\n[CRITICAL] Main, getting the {config_type} data from the nG1 API has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Convert the json nested dictionary to a flatend dataframe in pandas.
    status, right_now_df = convert_json_dict_to_dataframe(config_data, config_type, logger)
    if status == False: # The conversion has failed. Exit.
        logger.critical(f"[CRITICAL] Main, dataframe conversion has failed")
        print(f"\n[CRITICAL] Main, dataframe conversion has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    if config_current_is_found is True: # A 'current' CSV was found. Compare the desired current config to what is set in the nG1 configuration.
        status, did_anything_change, diff_df = get_config_data_differences(current_df, right_now_df, config_type, logger)
        if status == False: # The get config data differences has failed.
            logger.critical(f"[CRITICAL] Main, get_config_data_differences has failed")
            print(f"\n[CRITICAL] Main, get_config_data_differences has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        if did_anything_change == True: # Changes have been found in the config settings since last program execution.
            # Write the "diff_df" pandas dataframe to a CSV file to capture the differences between the desired current CSV and the nG1 right now config.
            status = write_dataframe_to_csv(diff_df, change_log_csv, logger)
            if status == False: # The write dataframe to CSV file operation has failed. Exit.
                logger.critical(f"[CRITICAL] Main, write_dataframe_to_csv to CSV filename: {change_log_csv} has failed")
                print(f"\n[CRITICAL] Main, writing the differences dataframe to CSV file: {change_log_csv} has failed")
                print(f'Check the log file: {log_filename}. Exiting...')
                sys.exit()
            if is_set_config_true == True: #The user wants any differences found to be set via nG1 API
                status = set_config_differences(session, diff_df, config_type, logger)
                if status == False: # The write config differences to nG1 API has failed. Exit.
                    logger.critical(f"[CRITICAL] Main, set_config_differences has failed")
                    print(f"\n[CRITICAL] Main, set_config_differences has failed")
                    print(f'Check the log file: {log_filename}. Exiting...')
                    sys.exit()
                # Get config info from the nG1 API. We need to capture those new id numbers for any added config items.
                config_data = get_ng1_config(session, config_type, logger)
                if config_data == False: # Getting the config data from the nG1 API has failed. Exit.
                    logger.critical(f"[CRITICAL] Main, after the set operation, getting the {config_type} data from the nG1 API has failed")
                    print(f"\n[CRITICAL] Main, after the set operation, getting the {config_type} data from the nG1 API has failed")
                    print(f'Check the log file: {log_filename}. Exiting...')
                    sys.exit()
                # Convert the json nested dictionary to a flatend dataframe in pandas.
                status, right_now_df = convert_json_dict_to_dataframe(config_data, config_type, logger)
                if status == False: # The conversion has failed. Exit.
                    logger.critical(f"[CRITICAL] Main, dataframe conversion has failed")
                    print(f"\n[CRITICAL] Main, dataframe conversion has failed")
                    print(f'Check the log file: {log_filename}. Exiting...')
                    sys.exit()
                # Any added config items will have id numbers now. Write the updated config to the current config CSV file.
                status = write_dataframe_to_csv(right_now_df, config_current_csv, logger)
                if status == False: # The write config differences to nG1 API has failed. Exit.
                    logger.critical(f"[CRITICAL] Main, after the set operation, updating the current CSV file has failed")
                    print(f"\n[CRITICAL] Main, after the set operation, updating the current CSV file has failed")
                    print(f'Check the log file: {log_filename}. Exiting...')
                    sys.exit()
        else: # Nothing changed. Create a new current CSV based on what is configured in the nG1 right now.
            # This gives the user a template to modify in Excel.
            status = write_dataframe_to_csv(right_now_df, config_current_csv, logger)
            if status == False: # The write dataframe to CSV file operation has failed. Exit.
                logger.critical(f"[CRITICAL] Main, write_dataframe_to_csv to CSV file: {config_current_csv} has failed")
                print(f"\n[CRITICAL] Main, writing the {config_type} dataframe to CSV file: {config_current_csv} has failed")
                print(f'Check the log file: {log_filename}. Exiting...')
                sys.exit()
    else: # No config current CSV file was found. Create one based on what is configured in the nG1 right now.
        # This gives the user a template to modify in Excel.
        status = write_dataframe_to_csv(right_now_df, config_current_csv, logger)
        if status == False: # The write dataframe to CSV file operation has failed. Exit.
            logger.critical(f"[CRITICAL] Main, write_dataframe_to_csv to CSV file: {config_current_csv} has failed")
            print(f"\n[CRITICAL] Main, writing the {config_type} dataframe to CSV file: {config_current_csv} has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

    # We are all finished, close the nG1 API session.
    if close_session(session, logger) == False: # Failed to close the API session.
        logger.critical(f"[CRITICAL] Main, close_session has failed")
        print(f"\n[CRITICAL] Main, Unable to close the nG1 API session")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    print(f'[iNFO] The CSV file: {config_current_csv} was created at {time.ctime()}')
    logger.info(f'[INFO] The CSV file: {config_current_csv} was created at {time.ctime()}')
    print('[INFO] Program execution has completed Successfully')
    logger.info('[INFO] Program execution has completed Successfully')

if __name__ == "__main__":
    main()
