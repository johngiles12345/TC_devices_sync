#!/usr/bin/env python3.8

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
from io import StringIO
import pprint
import argparse
import cmath
import ast
import chardet


"""
A python program for Transcanada that integrates MIB II device attributes found in their Solarwinds CSV export
to the nGeniusONE device configuration to produce a specific Network Service name that contains the desired fields from both.
Then that network service is placed into the dashboard hierarchy based on location names used to produce the Network Service name (label).
The new network service is added to the correct domain in the dashboard hierarchy.

"""

__version__ = "0.6"
__status__ = "beta"
__author__ = "John Giles"
__date__ = "2021 August 27th"
__env__= "Windows/Linux"
__Language__ = "Python v3"

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
    """Allows the user add optional flags to the launch command.
    Adding --set flag will tell the program to both get the nG1 config and set the nG1 config to
     match the "current" Solarwinds file.
    If the --set flag is not specified by the user, the program will gather the current nG1 config and
    the current Solarwinds config. Then it will merge the required columns and produce a
    net_srv_add_candidates.csv file.
    Then it will exit without performing any set commands to nG1 (will not sync the current Solarwinds file
    to the actual nG1 configuration).
    :program_version: Pass in the program version so the user can type --version.
    :logger: An instance of the logger class so we can write error messages if they occur.
    """
    try:
        # Define the program description
        text = 'This program is used to configure nGeniusONE network services and dashboard domains.'
        # Initiate the parser with a description
        parser = argparse.ArgumentParser(description=text)
        parser.add_argument('--set', '-s', action="store_true", help='set the nGeniusONE config to match the solarwinds_config_current.csv', dest='set', default=False)
        parser.add_argument('--version', '-v', action="store_true", help="show program version and exit", dest='version', default=False)
        # Parse the arguments and create a result.
        args = parser.parse_args()
        if args.version == True: # They typed either "-v" or "--version" flags.
            print(f'Program version is: {prog_version}')
            sys.exit(0)
        if args.set == True: # They typed either "-s" or "--set" flags.
            is_set_config_true = True # I need to do both a get and a set operation.
        else:
            is_set_config_true = False # I only need to do a get operation.

        return True, is_set_config_true
    except Exception: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] Parsing the run command arguments has failed')
        is_set_config_true = False

        return False, is_set_config_true

def create_logging_function(log_filename):
    """Creates the logging function and specifies a log file to write to that is date-time stamped.
    :log_filename: The name of the log file to write to.
    :return: The logger instance if successfully completed, Return False if not successful.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.

    try:
        logger = logging.getLogger('TC_devices_sync LOG')
        logger.setLevel(logging.DEBUG)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        fh = logging.FileHandler(log_filename)
        fh.setLevel(logging.DEBUG)

        formatter1 = logging.Formatter('%(levelname)s - %(message)s')
        formatter2 = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        ch.setFormatter(formatter1)
        fh.setFormatter(formatter2)

        logger.addHandler(ch)
        logger.addHandler(fh)

        logger.debug(f"*** Start of logs {date_time} ***")
        return logger
    except:
        print('Unable to create log file.')
        return None

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
            logger.critical(f"Unable to open ng1key file: {ng1key_file}")
            logger.critical(f'I/O error({e.errno}):  {e.strerror}.')
            print('Did you run the cred_script_nG1.py first?')
        except Exception:
            logger.exception(f"[ERROR] Fatal error: Unable to open ng1key_file: {ng1key_file}")
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
        logger.error(f"Unable to open cred_filename: {cred_filename}")
        logger.error(f'I/O error({e.errno}):  {e.strerror}.')
        return False
    except Exception: # Handle other unexpected errors.
        logger.exception(f"Fatal error: Unable to open cred_filename: {cred_filename}")
        return False

    return creds # The function was successful.

def determine_ng1_api_params(creds, logger):
    """Based on the values in the creds instance, determine what all the nG1 API connection and authentication parameters are.
    :creds: A class instance that holds all our nG1 connection and user authentication credentials values.
    :logger: An instance of the logger class so we can write error messages if they occur.
    :return: If successful, return status = True and the session = the nG1 API parameters for ng1_host, headers, cookies and credentials.
    Return None and status = False if any error occurrs.
    """

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
            logger.critical(f'nG1 destination port {creds.ng1Port} is not equal to 80, 8080, 443 or 8443')
            return False, None # Return status = False and session = None
        # Build up the base URL to use for all nG1 API calls.
        session.ng1_host = web_protocol + creds.ng1hostname + ':' + creds.ng1Port

        # Hardcoding the HTTP header to use in all the nG1 API calls.
        # Specifies the JSON data type as the format of the data we want returned by the nG1 API.
        session.headers = {
            'Cache-Control': "no-cache",
            'Accept': "application/json",
            'Content-Type': "application/json"
        }
    except Exception:
        logger.exception(f'Unable to create log file function for: {log_filename}')
        return False, None # Return status = False and session = None

    return True, session # As we are returning multiple params, we will status to set True or False.

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
            logger.critical(f'opening session to URL: {url} failed.')
            logger.critical('Unable to determine authentication by credentials or token.')
            return False
        if post.status_code == 200: # The nG1 API call was successful.
            logger.info(f'Opened Session to URL: {url} Successfully')
            # Utilize the returned cookie for future authentication. Keep this session open for all nG1 API calls.
            session.cookies = post.cookies # Set the session.cookies param to equal the Web RequestsCookieJar value.
            return True
        else: # We reached the nG1, but the request has failed. A different HTTP code other than 200 was returned.
            logger.critical(f'opening session to URL: {url} failed. Response Code: {post.status_code}. Response Body: {post.text}.')
            return False
    except Exception: # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.exception('Opening the nG1 API session, an exception has occurred.')
        logger.critical(f'Cannot reach URL: {url}')
        logger.critical('Check the VPN or internet connection')
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
            logger.info('Closed nG1 API Session Successfully')
            return True # Success! We closed the API session.
        else: # The nG1 API call failed.
            logger.error(f'closing nG1 API session failed. Response Code: {close.status_code}. Response Body: {close.text}.')
            return False
    except Exception:
        # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.exception('Closing the nG1 API, an exception has occurred.')
        logger.critical('We did not reach the nG1. Check your VPN or internect connection')
        return False

def get_provider_list(provider_list_filename, logger):
    """Look to see if a text file named the same as provider_list_filename is in the local directory.
    If so, read that into a list of valid service providers. if not, use a default static
    list of service provider names.
    :provider_list_filename: The name of the provider list text file.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the the provider list.
    Return status = False and None if there are any errors or exceptions.
    """
    provider_list = []
    try:
        # if provider_list.txt exists, read in contents to produce the list of provider names.
        if os.path.isfile(provider_list_filename):
            with open(provider_list_filename, 'r') as fh:
                logger.info(f'Provider list file: {provider_list_filename} was found and opened')
                lines = fh.readlines()
                if lines == None:
                    logger.error(f'There are no lines in the provider list text file: {provider_list_filename}')
                    return False, None
                else:
                    for line in lines:
                        line = line.strip()
                        provider_list.append(line)
                        #print(f'provider_list is: {provider_list}')
                    return True, provider_list
        else: # Use the default static list of provider names.
            provider_list = ['Armstrong', 'ATT ', 'AT&T', 'Axia', 'Bell', 'bell mobility', 'Bestel',
            'Bruce Knob Telephone', 'Casair Broadband', 'CenturyLink', 'Cinnnati Bell', 'Cogeco',
            'Cogen', 'Comcast Broadband', 'Comcast', 'Consolidated Communications DIA', 'Consolidated',
            'EIDNet', 'Elara', 'Frontier DIA', 'Frontier', 'GlobalGig Broadband', 'GlobalGig', 'Granite DIA',
            'Granite 10M DIA', 'Granite 20M DIA', 'Granite', 'GTT Service', 'GTT Broadband', 'IBM', 'Interstate-Telecom', 'ITC',
            'JBN Telephone Company',  'Lumen', 'LUS Fiber Broadband',
            'MCSNet', 'Nemont Telephone', 'New Windsor Telephone', 'NorthernTel', 'Norvado', 'Peninsula Fiber Network',
            'Pioneer Telephone Broadband', 'PS_LTE', 'Rogers', 'SageNet', 'Sandwich MICROWAVE', 'SaskTel',
            'Shaw Broadband', 'Shaw', 'Spacenet', 'Spectrum DIA', 'Spectrum Enterprise', 'Spectrum',
            'Starlink', 'TBayTel', 'TCT Broadband',
            'Telephone Broadband', 'Telcel', 'Telmex', 'Telemex', 'Telus', 'Verizon Broadband',
            'Verizon', 'Videotron', 'VzB', 'VZW', 'WiBand', 'Windstream',
            'Windstream DSL', 'Woodstock Communications', 'Xplonet', 'Xplornet', 'Zayo']
            return True, provider_list
    except IOError as err:
        logger.error(f'IO Error opening file: {provider_list_filename} Error message: {err}')
        return False, None
    except Exception:
        logger.error('An exception has occurred in get_provider_list')
        return False, None

def get_interface_type_list(interface_type_list_filename, logger):
    """Look to see if a text file named the same as interface_type_list_filename is in the local directory.
    If so, read that into a list of valid WAN interface types. if not, use a default static
    list of WAN interface types.
    :interface_type_list_filename: The name of the provider list text file.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the the WAN interface type list.
    Return status = False and None if there are any errors or exceptions.
    """
    interface_type_list = []
    try:
        # if interface_type_list.txt exists, read in contents to produce the list of WAN interface types.
        if os.path.isfile(interface_type_list_filename):
            with open(interface_type_list_filename, 'r') as fh:
                logger.info(f'WAN interface type list file: {interface_type_list_filename} was found and opened')
                lines = fh.readlines()
                if lines == None:
                    logger.error(f'There are no lines in the WAN interface type list text file: {interface_type_list_filename}')
                    return False, None
                else:
                    for line in lines:
                        line = line.strip()
                        interface_type_list.append(line)
                        #print(f'interface_type_list is: {interface_type_list}')
                    return True, interface_type_list
        else: # Use the default static list of WAN interface types.
            interface_type_list = ['Bell T1', 'Bell cell', 'Cell Modem', "cellular modem",
             'cell #', 'CenturyLink T1', 'CWAN', 'DSL', 'FlexVPN', 'GRE Tunnel', 'IPVPN',
             'LTE-', 'MPLS', 'MultiPoint',
             'PFN network DIA', 'rodgers cell', 'Verizon cell', 'VZW cell', 'VSAT']
            return True, interface_type_list
    except IOError as err:
        logger.error(f'IO Error opening file: {interface_type_filename} Error message: {err}')
        return False, None
    except Exception:
        logger.error('An exception has occurred in interface_type_list')
        return False, None

def check_illegal_characters(test, logger):
    """Iterate through all the characters in the the string test and look for any illegal
    characters. If an illegal character is found, remove it. Return the processed string.
    :test: A string to process for illegal characters.
    :logger: An instance of the logger class to write to in case of an error.
    Return the processed test string.
    """
    for char in test:
        if char in "[@!#$%^&*+=<>?|}{~]'":
            test = test.replace(char, '')
            logger.info(f'removed illegal char: {char}')
    return test

def get_devices(session, logger):
    """Use the nG1 API to get the current device configuration for MIBII devices in the system.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the the devices object.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/devices"
    url = session.ng1_host + uri
    try:
        # perform the HTTPS API call to get the devices information
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)

        if get.status_code == 200:
            # success
            logger.info(f'get devices nG1 API request Successful')
            devices_data=json.loads(get.text)
           # pprint.pprint(devices_data)
            filtered_devices_data = {'deviceConfigurations':[]}
            for device in devices_data['deviceConfigurations']:
                device_type = device['deviceType']
                device_status = device['status']
                device_name = device['deviceName']
                #print('\n' + device_name)
                if device_type == 'Router/Switch' and device_status == 'Active': # Only include Active MIBII devices.
                    device_server = device['nG1ServerName']
                if device_status == 'Active' and device_type == 'Router/Switch' and 'MIB-II DEVICE-' not in device_name: # Only include Active, MIBII devices that are not "MIB-II DEVICE-""
                    device['version'] = "N/A" # Fill in an empty field
                    device['wan_interfaces'] = [] # Initialize empty list to hold interfaces
                    filtered_devices_data['deviceConfigurations'].append(device)
            #print("\nfiltered_devices_data is:")
            #pprint.pprint(filtered_devices_data, indent=4)
            # Check for empty devices_data dict:
            if len(devices_data['deviceConfigurations']) < 1:
                    logger.error(f'No Active MIBII devices found in the nG1 configuration')
                    #print("\nfiltered_devices_data is:")
                    #pprint.pprint(filtered_devices_data, indent=4)
                    return False, None
            else:
                 return True, filtered_devices_data
        else:
            logger.error(f'get devices nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get devices nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def get_device_wan_interfaces(devices_config_data, interface_type_list, provider_list, session, logger):
    """Use the nG1 API to get all of the interface configuration that have "WAN" in the name
    for each MIB II device in the system. Append each WAN interface to the devices_config_data dict.
    :devices_config_data: A dictionary that contains the current nG1 active MIB II devices.
    :interface_type_list: A list of interface types (e.g., cellular modem, MPLS, etc.)
    :provider_list: A list of service provider names.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the appended devices_config_data.
    Return status = False and None if there are any errors or exceptions.
    """
    filtered_devices_config_data = {'deviceConfigurations':[]}
    try:
        for device in devices_config_data['deviceConfigurations']:
            #print(f"Inside, devices is {device}")
            device_name = device['deviceName']
            #print(f"Inside, deviceName is: {device_name}")
            status, interfaces_data = get_interfaces(device_name, interface_type_list, provider_list, session, logger)
            #print('\ninterfaces_data is:')
            #pprint.pprint(interfaces_data)
            if status == False:
                logger.critical(f"get_device_wan_speeds, get_interfaces has failed")
                return False, None
            elif status == True and interfaces_data == None: # No WAN interfaces were found
                continue
            for interface in interfaces_data['interfaceConfigurations']:
                interface_number = str(interface['interfaceNumber'])
                interface_name_to_modify = interface['interfaceName']
                #JUST for TESTING
                #interface_name_to_modify = interface['alias']
                status, modified_interface_name = modify_interface_name(interface_name_to_modify, logger)
                if status == False: # We were unable to modify the interface_name, use the original name
                    logger.error(f"Unable to translate interface port info for device: {device_name} interface name: {interface_name_to_modify}")
                    interface['interfaceName'] = 'no_if_port'
                    device['wan_interfaces'].append(interface)
                else: # The modification was successful, use the modified interface name
                    #print(f"{modified_interface_name=}")
                    device['wan_interfaces'].append(interface)
                    device['wan_interfaces'][0]['interfaceName'] = modified_interface_name
                device['wan_interfaces'][0]['RawInterfaceName'] = interface_name_to_modify
                break # We want to only process the first WAN interface.

            device['wanInterface'] = device['wan_interfaces'][0]['interfaceName']
            device['RawWanInterface'] = device['wan_interfaces'][0]['RawInterfaceName']
            device['interfaceType'] = device['wan_interfaces'][0]['interfaceType']
            device['wanSpeed'] = device['wan_interfaces'][0]['interfaceSpeed']
            device['interfaceNumber'] = device['wan_interfaces'][0]['interfaceNumber']
            device['interfaceAlias'] = device['wan_interfaces'][0]['alias']
            #device['interfaceMelid'] = device['wan_interfaces'][0]['melID']
            wan_speed = str(device['wanSpeed'])
            wan_speed_units = convert_wan_speed_to_units(wan_speed, logger)
            if wan_speed_units == False:
                logger.error(f"Conversion of WAN speed for device: {device_name} interface: {device['wanInterface']}")
                return False, None
            else:
                device['wanSpeedUnits'] = wan_speed_units
            device['alertProfileID'] = '' # Initialize an empty column to fill in later.
            device['wanProvider'] = device['wan_interfaces'][0]['provider']
            filtered_devices_config_data['deviceConfigurations'].append(device)
        #print('filtered devices config data is:')
        #pprint.pprint(filtered_devices_config_data)
        return True, filtered_devices_config_data
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get_device_wan_interfaces failed')
        return False, None

def modify_interface_name(interface_name, logger):
    """The name of the WAN interfaces as read from nG1 API need to be modified to
    match the desired name structure to be used as part of the network service name.
    :interface_name: A string that is the actual name of MIBII device's WAN interface.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the modified interface name.
    Return status = False and None if there are any errors or exceptions.
    """
    try:
        if 'GigabitEthernet' in interface_name:
            interface_name = 'Gi' + interface_name.partition('GigabitEthernet')[2]
        elif 'gigabitEthernet' in interface_name:
            interface_name = 'Gi' + interface_name.partition('gigabitEthernet')[2]
        elif 'gigabitethernet' in interface_name:
            interface_name = 'Gi' + interface_name.partition('gigabitethernet')[2]
        elif 'exs-1 g1/' in interface_name:
            interface_name = 'Gi' + interface_name.partition('exs-1 g')[2]
        elif 'FastEthernet' in interface_name:
            interface_name = 'Fa' + interface_name.partition('FastEthernet')[2]
        elif 'fastEthernet' in interface_name:
            interface_name = 'Fa' + interface_name.partition('fastEthernet')[2]
        elif 'fastethernet' in interface_name:
            interface_name = 'Fa' + interface_name.partition('fastethernet')[2]
        elif 'Tu1' in interface_name and 'Tu2' not in interface_name:
            interface_name = 'Tu1' + interface_name.partition('Tu1')[2]
        elif 'Tu2' in interface_name and 'Tu1' not in interface_name:
            interface_name = 'Tu2' + interface_name.partition('Tu2')[2]
        elif 'Tun1' in interface_name and 'Tun2' not in interface_name:
            interface_name = 'Tu1' + interface_name.partition('Tun1')[2]
        elif 'Tun2' in interface_name and 'Tun1' not in interface_name:
            interface_name = 'Tu2' + interface_name.partition('Tun2')[2]
        elif 'Tu1,Tu2' in interface_name in interface_name:
            interface_name = 'Tu1,Tu2' + interface_name.partition('Tu1,Tu2')[2]
        elif 'Tun1,Tun2' in interface_name in interface_name:
            interface_name = 'Tu1,Tu2' + interface_name.partition('Tun1,Tun2')[2]
        elif 'Tunnel' in interface_name:
            interface_name = 'Tu' + interface_name.partition('Tunnel')[2]
        elif 'tunnel' in interface_name:
            interface_name = 'Tu' + interface_name.partition('tunnel')[2]
        elif 'Serial' in interface_name:
            interface_name = 'Se' + interface_name.partition('Serial')[2]
        elif 'serial' in interface_name:
            interface_name = 'Se' + interface_name.partition('serial')[2]
        elif 's0' in interface_name:
            interface_name = 'Se' + interface_name.partition('s0')[2]
        elif 's1' in interface_name:
            intinterface_name = 'Se' + interface_name.partition('s1')[2]
        elif 's2' in interface_name:
            interface_name = 'Se' + interface_name.partition('s2')[2]
        elif 's3' in interface_name:
            iinterface_name = 'Se' + interface_name.partition('s3')[2]
        elif 'TenGigabitEthernet' in interface_name:
            interface_name = 'Te' + interface_name.partition('TenGigabitEthernet')[2]
        elif 'TEN' in interface_name:
            interface_name = 'Te' + interface_name.partition('TEN')[2]
        elif 'Ten' in interface_name:
            interface_name = 'Te' + interface_name.partition('Ten')[2]
        elif 'ten' in interface_name:
            interface_name = 'Te' + interface_name.partition('ten')[2]
        elif 'Multilink' in interface_name:
            interface_name = 'Mu' + interface_name.partition('Multilink')[2]
        elif 'multilink' in interface_name:
            interface_name = 'Mu' + interface_name.partition('multilink')[2]
        else:
            interface_name = 'no_if_port' # Default port info if no match.
    except Exception: # Handle other unexpected errors.
        logger.exception(f'modify_interface_name for: {interface_name} failed')
        return False, None
    return True, interface_name

def get_interfaces(device_name, interface_type_list, provider_list, session, logger):
    """Use the nG1 API to get the current interface configuration for each MIBII device in the system.
    If the interface name includes 'WAN', add it to the list of interfaces to return.
    :device_name: A string that is the name of nG1 device.
    :interface_type_list: A list of interface types (e.g., cellular modem, MPLS, etc.)
    :provider_list: A list of service provider names.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the interfaces info as a dict.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/devices/" + device_name + "/interfaces"
    url = session.ng1_host + uri

    try:
        # perform the HTTPS API call to get the devices information
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)

        if get.status_code == 200:
            # success
            logger.info(f'get interfaces for {device_name} nG1 API request Successful')
            interface_data=json.loads(get.text)
            filtered_interface_data = {'interfaceConfigurations':[]}
            for interface in interface_data['interfaceConfigurations']:
                #print('\ninterface data is:')
                #pprint.pprint(interface)
                if 'WAN' in interface['interfaceName']: # Only include WAN interfaces
                #if 'WAN' in interface['alias']: #JUST FOR TESTING
                    # Correct for bug in nG1 API
                    #print('I found WAN in the interface name')
                    interface['interfaceLinkType'] = interface['portSpeed']

                    interface['provider'] = 'no_prov' # Default string in case we don't get a match
                    for provider in provider_list:
                        # Note: For production switch back from alias to interfaceName!!
                        #if provider.lower() in interface['alias'].lower(): #JUST FOR TESTING
                        if provider.lower() in interface['interfaceName'].lower():
                            if provider.lower() == 'vzb':
                                interface['provider'] = 'Verizon'
                            elif provider.lower() == 'wiband':
                                interface['provider'] = 'WiBand Broadband'
                            elif provider.lower() == 'att ':
                                interface['provider'] = 'ATT'
                            else:
                                interface['provider'] = provider
                            #print(f'I found provider: {provider}')
                            break # Stop looking for the provider
                    #print(f"provider name inserted is: {interface['provider']}")

                    interface['interfaceType'] = 'no_if_type' # Default string in case we don't get a match
                    for interface_type in interface_type_list:
                        # Note: For production switch back from alias to interfaceName!!
                        #if interface_type.lower() in interface['alias'].lower(): #JUST FOR TESTING
                        if interface_type.lower() in interface['interfaceName'].lower():
                            if interface_type.lower() == 'ipvpn':
                                interface['interfaceType'] = 'MPLS'
                            elif interface_type.lower() == 'bell t1':
                                interface['interfaceType'] = 'T1'
                            elif interface_type.lower() == 'centurylink t1':
                                interface['interfaceType'] = 'T1'
                            elif interface_type.lower() == 'cell #':
                                interface['interfaceType'] = 'cell'
                            elif interface_type.lower() == 'bell cell':
                                interface['interfaceType'] = 'cell'
                            elif interface_type.lower() == 'verizon cell':
                                interface['interfaceType'] = 'cell'
                            elif interface_type.lower() == 'rogers cell':
                                interface['interfaceType'] = 'cell'
                            elif interface_type.lower() == 'vzw cell':
                                interface['interfaceType'] = 'cell'
                            elif interface_type.lower() == 'LTE-':
                                interface['interfaceType'] = 'LTE'
                            else:
                                interface['interfaceType'] = interface_type
                            #print(f'I found interface_type: {interface_type}')
                            break # Stop looking for the interface_type

                    # Only include interfaces that have "WAN" in the interface name.
                    filtered_interface_data['interfaceConfigurations'].append(interface)
                    break # Stop looking for the WAN interface
            if filtered_interface_data == {'interfaceConfigurations':[]}:
                #print(f"I did not find any WAN interfaces for device: {device_name}")
                return True, None # Signal the calling function that no WAN interfaces were found
            else:
                #print(f"I did find one or more WAN interfaces for device: {device_name}")
                return True, filtered_interface_data
        elif get.status_code == 404:
            logger.info(f'get interfaces for {device_name} return 404 not found')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return True, None
        else:
            logger.error(f'get interfaces nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get interfaces nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def get_services(session, logger):
    """Use the nG1 API to get the current services configuration. Filter to just the network services.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the network services info as a dict.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/services?type=network"
    url = session.ng1_host + uri

    try:
        # perform the HTTPS API call to get the network services current configuration
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)
        if get.status_code == 200:
            # success
            logger.info(f'get network services nG1 API request Successful')
            services_data=json.loads(get.text)
            return True, services_data
        elif get.status_code == 404:
            # No network services were found
            logger.info(f'get network services nG1 API request Successful')
            logger.info(f'No network services were found in the nG1 config')
            return True, None

        else:
            logger.error(f'get services nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get services nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def get_service_detail(session, service_name, logger):
    """Use the nG1 API to get the current services configuration. Filter to just the network services.
    :session: An instance of the ApiSession class that holds all our API session params.
    :service_name: A string that is the name of service you want to fetch.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the network services info as a dict.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/services/" + service_name
    url = session.ng1_host + uri

    try:
        # perform the HTTPS API call to get the service detail configuration
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)
        if get.status_code == 200:
            # success
            logger.info(f'get service detail for: {service_name} nG1 API request Successful')
            service_data=json.loads(get.text)
            return True, service_data
        elif get.status_code == 404:
            # No network services were found
            logger.info(f'get service for: {service_name} nG1 API request Successful')
            logger.info(f'No service: {service_name} was found in the nG1 config')
            return True, None

        else:
            logger.error(f'get service for: {service_name} nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get service for: {service_name} nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def convert_current_solarwinds_CSV_to_dataframe(config_current_csv, logger):
    """If found in the local directory, read the solarwinds_filename into a pandas dataframe for merging later.
    :config_current_csv: A string. The CSV filename of the current solarwinds config filename.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True, return the pandas dataframe.
    Return status = False and None if there are any errors or exceptions.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    try:
        # if config_current_csv exists read in as a pandas df, rename and cp current to archive then return the current df.
        if os.path.isfile(config_current_csv):
            #headers = pd.read_csv(config_current_csv, nrows=0).columns.tolist()
            columns = ['Caption', 'CorpSCADA_Type', 'LOB', 'MLOB', 'Site']
            current_df = pd.read_csv(config_current_csv, sep='\t', usecols=columns, engine='python', encoding='utf-16')
            #current_df_mod = current_df.rename(columns={'IP_Address': 'deviceIPAddress'}, axis='columns')
            logger.info(f"The solarwinds CSV file {config_current_csv} was found")
            current_df.rename({'IP_Address': 'deviceIPAddress'}, axis=1, inplace=True)
            current_df.rename({'Caption': 'deviceName'}, axis=1, inplace=True)
            #print(f'\nCurrent df is: \n{current_df}')
            logger.info(f"Conversion of CSV file: {config_current_csv} to a dataframe Successful")
            # The current dataframe may contain new rows where the id number is blank as new config items don't have an id yet.
            #current_df['id'] = current_df['id'].fillna(0) # Replace NaNs (empty id numbers) with zeros.
            return True, current_df
        else: # We did not find the config_current_csv file.
            return True, None
    except PermissionError as e:
        logger.info(f'Conversion of CSV file: {config_current_csv} to a dataframe has failed')
        logger.error (f"Permission error is:\n{e}")
        print('Do you have the file open?')
        return False, None
    except Exception: # An error has occurred, log the error and return a status of False.
        logger.exception(f'Conversion of config data to dataframe has failed')
        return False, None

def backup_current_CSV(config_current_csv, config_archive_csv, logger):
    """If this program has run before, there will be a "current" copy of the configuration CSV File.
    If found in the local directory, read it into a pandas dataframe for comparison later.
    If found in the local directory, rename it to "archive" with a time-date stamp.
    :config_current_csv: A string. The CSV filename of the current config created at the last run of this program.
    :config_archive_csv: A string. The CSV filename of the backup we will create if a "current" csv file exists.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True, return config_current_is_found = True is the "current" CSV file is found,
    or False if the file is not found, return the 'current' pandas dataframe holding the contents of the current CSV file.
        Return status = False, False and None if there are any errors or exceptions.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    try:
        # if config_current_csv exists read in as a pandas df, rename and cp current to archive then return the current df.
        if os.path.isfile(config_current_csv):
            print(f"Inside backup_current_CSV I found file {config_current_csv}")
            #with open(config_current_csv, 'rb') as f:
                #result = chardet.detect(f.read()) # or readline if the file is large

            #headers = pd.read_csv(config_current_csv, nrows=0).columns.tolist()
            columns = ['Caption','IP_Address', 'CorpSCADA_Type', 'LOB', 'MLOB', 'Site']
            current_df = pd.read_csv(config_current_csv, sep='\t', usecols=columns, engine='python', encoding='utf-16')
            #current_df = pd.read_csv(StringIO(config_current_csv), usecols=columns, sep=';',header=0, engine='python',encoding='utf-8-sig')
            #current_df=pd.read_csv(config_current_csv, sep=";", usecols = ['Caption','IP_Address', 'CorpSCADA_Type', 'LOB', 'MLOB', 'Site'], encoding=result['encoding'])
            #current_df = pd.read_csv(config_current_csv, encoding="ISO-8859???1")
            print(f'\nCurrent df is: \n{current_df}')
            #print(f'dtypes are: \n{current_df.dtypes}')
            #if config_type == 'sites':
                # Pandas dataframes don't have types of 'list' or 'dict', so we need to convert any of these to strings.
                #current_df['IP_Address'] = current_df.IP_Address.astype('str') # Cast the list of ipaddress ranges into a string.
            config_archive_csv = config_archive_csv + '_' + str(date_time) + '.csv'
            #current_df = current_df[['id','name', 'addresses', 'speedKbps']] # reorder the columns.
            os.rename(config_current_csv, config_archive_csv) # rename the current CSV file to a time-date stamped archive CSV file.
            logger.info(f"Backing up file {config_current_csv} to {config_archive_csv} Successful")
            # The current dataframe may contain new rows where the id number is blank as new config items don't have an id yet.
            #current_df['id'] = current_df['id'].fillna(0) # Replace NaNs (empty id numbers) with zeros.
            return True, True, current_df
        else: # We did not find the config_current_csv file.
            print(f"Inside backup_current_CSV I did NOT find the file {config_current_csv}")
            return True, False, None
    except PermissionError as e:
        logger.info(f'Conversion of CSV file: {config_current_csv} to a dataframe has failed')
        logger.error (f"Permission error is:\n{e}")
        print('Do you have the file open?')
        return False, False, None
    except Exception: # An error has occurred, log the error and return a status of False.
        logger.exception(f'Conversion of config data to dataframe has failed')
        return False, False, None

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
            fieldnames = ['Infinistream', 'interfaceName', 'alias', 'interfaceNumber', 'interfaceSpeed', 'interfaceSpeed', 'status', 'alarmTemplateName', 'virtulization', 'activeInterfaces', 'inactiveInterfaces', 'interfaceLinkType', 'nBAnASMonitoring']
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
        logger.error(f'Unable to write Interface Locations to the CSV file: {filename}')
        logger.error(f'I/O error({e.errno}):  {e.strerror}.')
        return False
    except Exception: # Handle other exceptions such as attribute errors.
        logger.exception(f"Unable to write Interface Locations to the CSV file: {filename}")
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
    elif config_type == 'devices':
        column_headers = ['deviceName', 'deviceIPAddress', 'wanInterface', 'RawWanInterface', 'interfaceType',
        'interfaceAlias', 'wanSpeed', 'interfaceNumber', 'wanSpeedUnits', 'wanProvider', 'alertProfileID']
    elif config_type == 'interfaces':
        column_headers = ['deviceName', 'deviceIPAddress', 'interfaceName', 'interfaceNumber',
        'interfaceSpeed', 'interfaceLinkType', 'status']
    elif config_type == 'client_comm':
        column_headers = ['CHANGE ME']
    elif config_type == 'apps':
        column_headers = ['CHANGE ME']
    else:
        logger.info(f'Unable to set differences, config type {config_type} is invalid')
        return False
    try:
        # Initialize an empty list to hold the per-interface data.
        rows = []
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

        return True, df_right_now # You can't have a whole dataframe be either True or False. So we add a status boolean.
    except Exception:
        logger.exception(f'Conversion of JSON config data to dataframe has failed')
        return False, None

def write_dataframe_to_csv(df, csv_filename, logger):
    """Write the Pandas dataframe to a CSV file.
    :df: The dataframe of nG1 config data collected.
    :csv_filename: The name of the CSV file to write to.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    try:
        df.to_csv(csv_filename, header=True, encoding='utf-8', index=False) # Write the dataframe to the CSV file.
    except PermissionError as e:
        logger.error(f'Permission Error: Write dataframe to CSV file: {csv_filename}')
        logger.error(f'Permission Error({e.errno}):  {e.strerror}.')
        print('Do you have the file open?')
        status = False
        config_current_is_found = False
        current_df = ''
        return status, config_current_is_found, current_df
    except IOError as e: # Handle file I/O errors.
        print(f'\n[ERROR] I/O error: Write dataframe to CSV file: {csv_filename}')
        logger.error(f'[ERROR] I/O Error: Write dataframe to CSV file: {csv_filename}')
        logger.error(f'[ERROR] I/O Error({e.errno}):  {e.strerror}.')
    except Exception:
        logger.exception(f'Write dataframe to CSV file: {csv_filename} has failed"')
        return False
    logger.info(f'Write dataframe to CSV file: {csv_filename} Successful"')
    return True

def find_intersection_solarwinds_to_current_device_interfaces(solarwinds_current_df, right_now_df, logger):
    """Based on IP address, find the intersection of solarwinds WAN interfaces and nG1 MIB II device interfaces.
    :solarwinds_current_df: The dataframe of the current configuration in solarwinds.
    :right_now_df: The datafram of the current nG1 device interface configuration.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True and the dataframe intersection where IP addresses match.
    Return status = False and None if there are any errors or exceptions.
    """
    try:
        intersection_df = pd.merge(solarwinds_current_df, right_now_df, how ='inner', on =['deviceName'])
        #print("\nintersection_df is:")
        #print(intersection_df)
        return True, intersection_df
    except Exception:
        logger.exception(f'find_intersection_solarwinds_to_current_device_interfaces has failed"')
        return False, None

def get_service_alert_profiles(session, logger):
    """Use the nG1 API to get the current alert profiles configuration for network service type.
    Only alert profiles where the ServiceType is 'NetworkService' will be returned.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the alert profiles info as a dict.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/servicealertprofiles"
    url = session.ng1_host + uri

    try:
        # perform the HTTPS API call to get the alert profiles information
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)
        if get.status_code == 200:
            # success
            logger.info(f'get alert profiles nG1 API request Successful')
            alert_profiles_data=json.loads(get.text)
            filtered_alert_profiles_data = {'AlarmProfiles':[]}
            for alert_profile in alert_profiles_data['AlarmProfiles']: #Only include NetworkService profiles
                if alert_profile['ServiceType'] == 'NetworkService' and '_Link_BitRate' in alert_profile['Name']:
                    filtered_alert_profiles_data['AlarmProfiles'].append(alert_profile)
            return True, filtered_alert_profiles_data
        elif get.status_code == 404:
            # No network services were found
            logger.info(f'get alert profiles nG1 API request Successful')
            logger.info(f'No alert profiles were found in the nG1 config')
            return True, None
        else:
            logger.error(f'get alert profiles nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get alert profiles nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def convert_wan_speed_to_units(interface_speed, logger):
    """Format the bps interface speed value into a value + units combination (i.e., 100 Mbps).
    :interface_speed: A string that is the bits per second bandwidth speed of the interface.
    :logger: An instance of the logger class to write to in case of error or exception.
    :return: If successful, return the wan_units string.
    Return status = False if there are any errors.
    """
    if interface_speed == '32000':
        wan_units = '32 Kbps'
    elif interface_speed == '56000':
        wan_units = '56 Kbps'
    elif interface_speed == '100000':
        wan_units = '100 Kbps'
    elif interface_speed == '128000':
        wan_units = '128 Kbps'
    elif interface_speed == '256000':
        wan_units = '256 Kbps'
    elif interface_speed == '300000':
        wan_units = '300 Kbps'
    elif interface_speed == '384000':
        wan_units = '384 Kbps'
    elif interface_speed == '400000':
        wan_units = '400 Kbps'
    elif interface_speed == '500000':
        wan_units = '500 Kbps'
    elif interface_speed == '512000':
        wan_units = '512 Kbps'
    elif interface_speed == '600000':
        wan_units = '600 Kbps'
    elif interface_speed == '800000':
        wan_units = '800 Kbps'
    elif interface_speed == '896000':
        wan_units = '896 Kbps'
    elif interface_speed == '1000000':
        wan_units = '1 Mbps'
    elif interface_speed == '1024000':
        wan_units = '1.024 Mbps'
    elif interface_speed == '1200000':
        wan_units = '1.2 Mbps'
    elif interface_speed == '1250000':
        wan_units = '1.25 Mbps'
    elif interface_speed == '1280000':
        wan_units = '1.28 Mbps'
    elif interface_speed == '1400000':
        wan_units = '1.4 Mbps'
    elif interface_speed == '1500000':
        wan_units = '1.5 Mbps'
    elif interface_speed == '1536000':
        wan_units = '1.536 Mbps'
    elif interface_speed == '1544000':
        wan_units = '1.544 Mbps'
    elif interface_speed == '1800000':
        wan_units = '1.8 Mbps'
    elif interface_speed == '2000000':
        wan_units = '2 Mbps'
    elif interface_speed == '2400000':
        wan_units = '2.4 Mbps'
    elif interface_speed == '2500000':
        wan_units = '2.5 Mbps'
    elif interface_speed == '2600000':
        wan_units = '2.6 Mbps'
    elif interface_speed == '2800000':
        wan_units = '2.8 Mbps'
    elif interface_speed == '3000000':
        wan_units = '3 Mbps'
    elif interface_speed == '3500000':
        wan_units = '3.5 Mbps'
    elif interface_speed == '4000000':
        wan_units = '4 Mbps'
    elif interface_speed == '4500000':
        wan_units = '4.5 Mbps'
    elif interface_speed == '4600000':
        wan_units = '4.6 Mbps'
    elif interface_speed == '5000000':
        wan_units = '5 Mbps'
    elif interface_speed == '5890000':
        wan_units = '5.89 Mbps'
    elif interface_speed == '6000000':
        wan_units = '6 Mbps'
    elif interface_speed == '6500000':
        wan_units = '6.5 Mbps'
    elif interface_speed == '7000000':
        wan_units = '7 Mbps'
    elif interface_speed == '8000000':
        wan_units = '8 Mbps'
    elif interface_speed == '9000000':
        wan_units = '9 Mbps'
    elif interface_speed == '9600000':
        wan_units = '9.6 Mbps'
    elif interface_speed == '10000000':
        wan_units = '10 Mbps'
    elif interface_speed == '10500000':
        wan_units = '10.5 Mbps'
    elif interface_speed == '12000000':
        wan_units = '12 Mbps'
    elif interface_speed == '14000000':
        wan_units = '14 Mbps'
    elif interface_speed == '15000000':
        wan_units = '15 Mbps'
    elif interface_speed == '18000000':
        wan_units = '18 Mbps'
    elif interface_speed == '18500000':
        wan_units = '18.5 Mbps'
    elif interface_speed == '19000000':
        wan_units = '19 Mbps'
    elif interface_speed == '20000000':
        wan_units = '20 Mbps'
    elif interface_speed == '23000000':
        wan_units = '23 Mbps'
    elif interface_speed == '30000000':
        wan_units = '30 Mbps'
    elif interface_speed == '35000000':
        wan_units = '35 Mbps'
    elif interface_speed == '40000000':
        wan_units = '40 Mbps'
    elif interface_speed == '45000000':
        wan_units = '45 Mbps'
    elif interface_speed == '47000000':
        wan_units = '47 Mbps'
    elif interface_speed == '49000000':
        wan_units = '49 Mbps'
    elif interface_speed == '50000000':
        wan_units = '50 Mbps'
    elif interface_speed == '60000000':
        wan_units = '60 Mbps'
    elif interface_speed == '80000000':
        wan_units = '80 Mbps'
    elif interface_speed == '97000000':
        wan_units = '97 Mbps'
    elif interface_speed == '100000000':
        wan_units = '100 Mbps'
    elif interface_speed == '150000000':
        wan_units = '150 Mbps'
    elif interface_speed == '196000000':
        wan_units = '196 Mbps'
    elif interface_speed == '200000000':
        wan_units = '200 Mbps'
    elif interface_speed == '250000000':
        wan_units = '250 Mbps'
    elif interface_speed == '300000000':
        wan_units = '300 Mbps'
    elif interface_speed == '500000000':
        wan_units = '500 Mbps'
    elif interface_speed == '512000000':
        wan_units = '512 Mbps'
    elif interface_speed == '950000000':
        wan_units = '950 Mbps'
    elif interface_speed == '1000000000':
        wan_units = '1 Gbps'
    elif interface_speed == '2000000000':
        wan_units = '2 Gbps'
    elif interface_speed == '2400000000':
        wan_units = '2.4 Gbps'
    elif interface_speed == '2500000000':
        wan_units = '2.5 Gbps'
    elif interface_speed == '2600000000':
        wan_units = '2.6 Gbps'
    elif interface_speed == '2800000000':
        wan_units = '2.8 Gbps'
    elif interface_speed == '10000000000':
        wan_units = '10 Gbps'
    else:
        logger.error(f"No matching WAN units for interface speed of: {interface_speed}")
        return False
    return wan_units

def create_alert_profile_ids_dict(alert_profiles_data, logger):
    """Create a python dictionary that holds the key:value pairs of wan speed to alert profile id number.
    :alert_profiles_data: A dict that holds the current nG1 alert profile configuration.
    :logger: An instance of the logger class to write to in case of error or exception.
    :return: If successful, return status = True and the alert_profile_ids_dict.
    Return status = False and None if there are any errors or exceptions.
    """
    alert_profiles_ids_dict = {}
    #print(f'\nalert_profiles_data is: ')
    #pprint.pprint(alert_profiles_data)
    #print('\n')

    try:
        for alert_profile in alert_profiles_data['AlarmProfiles']:
            alert_profile_name = alert_profile['Name']
            if alert_profile_name.startswith("0.032Mbps"):
                  alert_profiles_ids_dict['32000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.056Mbps"):
                alert_profiles_ids_dict['56000'] = alert_profile['Id']
            elif alert_profile_name.startswith("100Kbps"):
                alert_profiles_ids_dict['100000'] = alert_profile['Id']
            elif alert_profile_name.startswith("128Kbps"):
                alert_profiles_ids_dict['128000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.256Mbps"):
                alert_profiles_ids_dict['256000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.3Mbps"):
                alert_profiles_ids_dict['300000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.384Mbps"):
                alert_profiles_ids_dict['384000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.4Mbps"):
                alert_profiles_ids_dict['400000'] = alert_profile['Id']
            elif alert_profile_name.startswith("512Kbps"):
                alert_profiles_ids_dict['512000'] = alert_profile['Id']
            elif alert_profile_name.startswith("500Kbps"):
                alert_profiles_ids_dict['500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.6Mbps"):
                alert_profiles_ids_dict['600000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.8Mbps"):
                alert_profiles_ids_dict['800000'] = alert_profile['Id']
            elif alert_profile_name.startswith("0.896Mbps"):
                alert_profiles_ids_dict['896000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1.024Mbps"):
                 alert_profiles_ids_dict['1024000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1Mbps"):
                 alert_profiles_ids_dict['1000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1.2Mbps"):
                alert_profiles_ids_dict['1200000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1.25Mbps"):
                alert_profiles_ids_dict['1250000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1.28Mbps"):
                alert_profiles_ids_dict['1280000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1.4Mbps"):
                alert_profiles_ids_dict['1400000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1.5Mbps"):
                alert_profiles_ids_dict['1500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1536Kbps"):
                alert_profiles_ids_dict['1536000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1544Kbps"):
                alert_profiles_ids_dict['1544000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1.8Mbps"):
                alert_profiles_ids_dict['1800000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2Mbps"):
                alert_profiles_ids_dict['2000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.4Mbps"):
                alert_profiles_ids_dict['2400000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.5Mbps"):
                alert_profiles_ids_dict['2500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.6Mbps"):
                alert_profiles_ids_dict['2600000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.8Mbps"):
                alert_profiles_ids_dict['2800000'] = alert_profile['Id']
            elif alert_profile_name.startswith("3Mbps"):
                alert_profiles_ids_dict['3000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("3.5Mbps"):
                alert_profiles_ids_dict['3500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("4Mbps"):
                alert_profiles_ids_dict['4000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("4.5Mbps"):
                alert_profiles_ids_dict['4500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("4.6Mbps"):
                alert_profiles_ids_dict['4600000'] = alert_profile['Id']
            elif alert_profile_name.startswith("5Mbps"):
                alert_profiles_ids_dict['5000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("5.89Mbps"):
                alert_profiles_ids_dict['5890000'] = alert_profile['Id']
            elif alert_profile_name.startswith("6Mbps"):
                alert_profiles_ids_dict['6000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("6.5Mbps"):
                alert_profiles_ids_dict['6500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("7Mbps"):
                alert_profiles_ids_dict['7000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("8Mbps"):
                alert_profiles_ids_dict['8000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("9Mbps"):
                alert_profiles_ids_dict['9000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("9.6Mbps"):
                alert_profiles_ids_dict['9600000'] = alert_profile['Id']
            elif alert_profile_name.startswith("10Mbps"):
                alert_profiles_ids_dict['10000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("10.5Mbps"):
                alert_profiles_ids_dict['10500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("12Mbps"):
                alert_profiles_ids_dict['12000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("14Mbps"):
                alert_profiles_ids_dict['14000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("15Mbps"):
                alert_profiles_ids_dict['15000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("18Mbps"):
                alert_profiles_ids_dict['18000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("18.5Mbps"):
                alert_profiles_ids_dict['18500000'] = alert_profile['Id']
            elif alert_profile_name.startswith("19Mbps"):
                alert_profiles_ids_dict['19000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("20Mbps"):
                alert_profiles_ids_dict['20000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("23Mbps"):
                alert_profiles_ids_dict['23000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("30Mbps"):
                alert_profiles_ids_dict['30000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("35Mbps"):
                alert_profiles_ids_dict['35000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("40Mbps"):
                alert_profiles_ids_dict['40000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("45Mbps"):
                alert_profiles_ids_dict['45000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("47Mbps"):
                alert_profiles_ids_dict['47000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("49Mbps"):
                alert_profiles_ids_dict['49000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("50Mbps"):
                alert_profiles_ids_dict['50000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("60Mbps"):
                alert_profiles_ids_dict['60000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("80Mbps"):
                alert_profiles_ids_dict['80000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("97Mbps"):
                alert_profiles_ids_dict['97000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("100Mbps"):
                alert_profiles_ids_dict['100000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("150Mbps"):
                alert_profiles_ids_dict['150000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("196Mbps"):
                alert_profiles_ids_dict['196000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("200Mbps"):
                alert_profiles_ids_dict['200000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("250Mbps"):
                alert_profiles_ids_dict['250000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("300Mbps"):
                alert_profiles_ids_dict['300000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("512Mbps"):
                alert_profiles_ids_dict['512000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("500Mbps"):
                alert_profiles_ids_dict['500000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("950Mbps"):
                alert_profiles_ids_dict['950000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("1Gbps"):
                alert_profiles_ids_dict['1000000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2Gbps"):
                alert_profiles_ids_dict['2000000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.4Gbps"):
                alert_profiles_ids_dict['2400000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.5Gbps"):
                alert_profiles_ids_dict['2500000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.6Gbps"):
                alert_profiles_ids_dict['2600000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("2.8Gbps"):
                alert_profiles_ids_dict['2800000000'] = alert_profile['Id']
            elif alert_profile_name.startswith("10Gbps"):
                alert_profiles_ids_dict['10000000000'] = alert_profile['Id']
            else:
                logger.info(f"No matching speed for alert_profile name {alert_profile['Name']}")
                continue

    except Exception: # Handle other unexpected errors.
        logger.exception(f'get alert profiles id to dict operation failed')
        return False, None

    return True, alert_profiles_ids_dict

def add_alert_profile_ids(intersection_df, alert_profiles_ids_dict, logger):
    """For each row in intersection_df, read the wanSpeed value and lookup the alert profile id number in
    the alert_profiles_data. Add this value to the new column called 'alertProfileID' in intersection_df. This
    way we have the correct id number for each MIBII device to use when creating the network service.
    :intersection_df: The dataframe that holds matching MIBII devices in nG1 to those listed in the solarwinds_filename.
    :alert_profiles_ids_dict: A dict that holds the current nG1 alert profile id numbers for each wan speed value.
    :logger: An instance of the logger class that we can write to if there is an error or exception.
    :return: If successful, return status = True and the updated intersection_df that includes alert id values.
    Return status = False and None if there are any errors or exceptions.
    """
    #print("\nalert_profiles_ids_dict is:")
    #pprint.pprint(alert_profiles_ids_dict)
    for index, row in intersection_df.iterrows():
        wan_speed = str((row['wanSpeed']))
        #print(f'\nlooking for WAN speed {wan_speed}')

        if wan_speed in alert_profiles_ids_dict.keys():
            #print(f"{alert_profiles_ids_dict[wan_speed]=}")
            #print(f'Found WAN speed {wan_speed} in the alert_profiles_ids_dict')
            intersection_df.at[index, "alertProfileID"] = str(alert_profiles_ids_dict[wan_speed])
        else:
            logger.error(f"The wan_speed {wan_speed} was not found in the alert_profiles_ids_dict")
            return False, None
    return True, intersection_df

def create_network_service_configs(session, is_set_config_true, MIBII_network_services, net_srv_add_candidates_filename, intersection_df, logger):
    """Take the information in the intersection_df and for each MIBII device, create a network service definition
    if it has a qualified service provider WAN interface. Then call the function to create each network service using the nG1 API.
    For each service that is created, get the service ID number fron nG1 API,
    then add the network service name and id number to new columns in the intersection_df.
    Add any valid network service candidates for adding to a csv file that we can use for troubleshooting.
    We will need those ID numbers to place them into the dashboard later.
    Add any new network service names that don't already exist to list new_MIBII_network_service_names.
    We will use new_MIBII_network_service_names to determine which new network services to add to the domain tree.
    :session: An instance of the ApiSession class that holds all our API session params.
    :is_set_config_true: A boolean that tells the system to perform set operations if True.
    :MIBII_network_services: A list of network service names ending in '_MIB Polling'.
    :net_srv_add_candidates_filename: The name of the csv file to write the candidates for new network service creation into.
    :intersection_df: The dataframe that holds matching MIBII devices in nG1 to those listed in the solarwinds_filename.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True, the modified intersection_df, a list of valid_MIBII_network_service_names
    and a list of new_MIBII_network_service_names.
    Return False, None, None and None if there are any errors or exceptions.
    Return None, the modified intersection_df, a list of valid_MIBII_network_service_names and new_MIBII_network_service_names
    if there are no new WAN interfaces to add or any modifications to make.
    """
    # We will return a status of None if there are no additions or modifications to make.
    adds_or_mods_counter = 0
    # Even if there are no modifications to make, we will return the data so that candidates for deletion can be performaned.
    valid_MIBII_network_service_names = []
    # If there are new network services to add, put them into a list for us to use when creating domians.
    new_MIBII_network_service_names = []
    try:
        with open(net_srv_add_candidates_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Network Service Name to add'])
            for index, row in intersection_df.iterrows():
                site = row['Site']
                provider = row['wanProvider']
                interface_type = row['interfaceType']
                corpscada_type = row['CorpSCADA_Type']
                if corpscada_type == "corp_and_scada":
                    corpscada_type = "Corp/SCADA"
                device_name = row['deviceName']
                device_ip_address = row['deviceIPAddress']
                wan_interface = row['wanInterface']
                wan_speed_units = row['wanSpeedUnits']
                alert_profile_id = int(row['alertProfileID'])
                interface_number = int(row['interfaceNumber'])
                interface_alias = row['interfaceAlias']
                network_service_name = site + '_' + provider + ' ' + interface_type + '-' + corpscada_type + ' WAN (' + device_name + ' if: ' + wan_interface + '-' + wan_speed_units + ')_MIB Polling'
                # Check for illegal characters.
                network_service_name = check_illegal_characters(network_service_name, logger)
                intersection_df.at[index, "netServiceName"] = network_service_name

                svcs_dict={}
                svcs_ary=[]
                svc_dict={}
                svc_members_ary=[]
                svc_member_dict={}

                svc_dict['serviceType']=6
                svc_dict['alertProfileID']=alert_profile_id
                svc_dict['isAlarmEnabled']= True
                svc_member_dict['enableAlert']= True
                svc_member_dict['ipAddress']= device_ip_address
                svc_member_dict['meName']= device_name + ":" + wan_interface
                svc_member_dict['meAlias']=interface_alias
                #svc_member_dict['melID']=10000168
                svc_members_ary.append(svc_member_dict.copy())
                svc_dict['serviceMembers']=svc_members_ary
                svc_dict['id']=-1
                svc_dict['serviceName']=network_service_name
                svcs_ary.append(svc_dict.copy())
                svcs_dict['serviceDetail']=svcs_ary

                #print('The data to be posted is : ')
                #print(svcs_dict)

                valid_MIBII_network_service_names.append(network_service_name)

                # Check to see if this device_name is already in an existing network service name.
                network_service_exists = False
                if MIBII_network_services != None:
                    for existing_network_service_name in MIBII_network_services:
                        if device_name in existing_network_service_name:
                            network_service_exists = True
                            break
                # This network service does not exist.
                # Add it to the net_srv_add_candidates.csv file
                if network_service_exists != True:
                    writer.writerow([network_service_name])
                    new_MIBII_network_service_names.append(network_service_name)
                    adds_or_mods_counter += 1

                # Create the new network service.
                if is_set_config_true == True: # Perform the set operations
                    status = create_service(session, svcs_dict, network_service_name, logger)
                    if status == False:
                        logger.error(f'create_service: {network_service_name} has failed')
                        return False, None, None, None
                    time.sleep(1) # Give it a second before we request the ID number.
                    # We need to know the id number that was assigned to this new network service, so we get_service_detail on it.
                    # We store this id number in the intersection_df so that later we can add it as a member to to the region domain.
                    status, net_srv_config_data = get_service_detail(session, network_service_name, logger)
                    if status == False:
                        logger.error(f'create_service: {network_service_name} has failed')
                        logger.error(f'call to get_service_detail has failed')
                        return False, None, None, None
                    elif net_srv_config_data == None:
                        logger.error(f'create_service: {network_service_name} has failed')
                        logger.error(f'call to get_service_detail returned an empty net_srv_config_data')
                        return False, None, None, None
                    #print('\nnet_srv_config_data is:')
                    #print(f'{net_srv_config_data}')
                    net_srv_id = net_srv_config_data['serviceDetail'][0]['id']
                    intersection_df.at[index, "netServiceID"] = net_srv_id
        if adds_or_mods_counter > 0:
            logger.info(f'{adds_or_mods_counter} new network service add candidates found')
            logger.info(f'Candidates for new network services written to file: {net_srv_add_candidates_filename}')
        else:
            logger.info(f'There were no new network service add candidates found')
        csvfile.close()
    except PermissionError as e:
        logger.info(f'Opening file: {net_srv_add_candidates_filename} for writing has failed')
        logger.error (f"Permission error is:\n{e}")
        print('Do you have the file open?')
        return False, None, None, None
    except Exception: # Handle other unexpected errors.
        logger.exception('An exception has occurred during the create_network_service_configs operation')
        return False, None, None, None
    if adds_or_mods_counter == 0: # No new WAN interfaces to add and no mods to make.
        return None, intersection_df, valid_MIBII_network_service_names, new_MIBII_network_service_names
    else:
        return True, intersection_df, valid_MIBII_network_service_names, new_MIBII_network_service_names

def delete_orphan_services(session, is_set_config_true, MIBII_network_services, valid_MIBII_network_service_names, net_srv_delete_candidates_filename, logger):
    """Take in the a list of MIBII_network_services for MIBII WAN interfaces as it
    was prior to adding new services and compare it to the valid_MIBII_network_service_names for MIBII
    interfaces as it is now after the additions. Write the list of candidates for deletion to a CSV file.
    Remove any orphans from the configuration so that we can keep the configuration up to date.
    :session: An instance of the ApiSession class that holds all our API session params.
    :is_set_config_true: A boolean that tells the system to perform set operations if True.
    :MIBII_network_services: A list of the pre-addition network services with names ending in '_MIB Polling'
    :intersection_df: The dataframe that holds matching MIBII devices in nG1 to those listed in the solarwinds_filename.
    :net_srv_delete_candidates_filename: The filename of the csv file that lists all the network services that are orphaned.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True.
    Return False if there are any errors or exceptions.
    """
    delete_candidates_count = 0
    MIBII_network_service_names_to_delete = []
    try:
        with open(net_srv_delete_candidates_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Network Service Names to delete'])
            for MIBII_network_service in MIBII_network_services:
                # print(f'\nvalid_MIBII_network_service_names are: \n{valid_MIBII_network_service_names}')
                if MIBII_network_service not in valid_MIBII_network_service_names: # I found a candidate for deletion.
                    writer.writerow([MIBII_network_service])
                    MIBII_network_service_names_to_delete.append(MIBII_network_service)
                    delete_candidates_count += 1
            if delete_candidates_count > 0:
                logger.info(f'{delete_candidates_count} network service deletion candidates found')
                logger.info(f'Candidates for network service deletion written to file:: {net_srv_delete_candidates_filename}')
                #if is_set_config_true == True:
                    #for MIBII_network_service_name_to_delete in MIBII_network_service_names_to_delete:
                        #status = delete_service(session, MIBII_network_service_name_to_delete, logger)
                        #if status == False:
                            #logger.error(f'Delete service: {MIBII_network_service_name_to_delete} operation failed')
                            #return False
                #else:
                    #logger.info('No network service candidates for deletion were removed as the --set flag was not specified')
            else:
                logger.info(f'There were no network service deletion candidates found')
        csvfile.close()
    except PermissionError as e:
        logger.info(f'Opening file: {net_srv_delete_candidates_filename} for writing has failed')
        logger.error (f"Permission error is:\n{e}")
        print('Do you have the file open?')
        return False
    except Exception: # Handle other unexpected errors.
        logger.exception('An exception has occurred during the create_network_service_configs operation')
        return False
    return True

def create_service(session, config_data, service_name, logger):
    """Use the nG1 API to create a network service.
    :session: An instance of the ApiSession class that holds all our API session params.
    :config_data: A dict that holds the service configuration parameters.
    :service_name: The name of the service. Used for success or failure log posting.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/services"
    url = session.ng1_host + uri
    try:
        # use json.dumps to provide a serialized json object (a string actually).
        # this json_string will become our new configuration for this service_name.
        json_string = json.dumps(config_data)
        # perform the HTTPS API post to and pass in the serialized json object config_data
        post = requests.post(url, headers=session.headers, data=json_string, verify=False, cookies=session.cookies)

        if post.status_code == 200: # success
            logger.info(f'create service: {service_name} nG1 API POST Successful')
            return True
        else: # Create Service has failed.
            # If the service exists, don't post an error message, just show as info.
            if 'exists' in post.text:
                logger.info(f'create service: {service_name} already exists')
                return True
            else:
                logger.error(f'create service: {service_name} nG1 API request failed')
                logger.error(f'Response Code: {post.status_code}. Response Body: {post.text}.')
                return False
    except Exception: # Handle other unexpected errors.
        logger.exception(f'create service: {service_name} nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False

def delete_service(session, service_name, logger):
    """Use the nG1 API to delete a network service.
    :session: An instance of the ApiSession class that holds all our API session params.
    :service_name: The name of the service to delete.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/services"
    url = session.ng1_host + uri
    try:
        # perform the HTTPS DELETE operation
        resp = requests.delete(url, headers=session.headers, verify=False, cookies=session.cookies)

        if resp.status_code == 200: # success
            logger.info(f'delete service: {service_name} nG1 API DELETE Successful')
            return True
        else: # Delete Service has failed.
            logger.error(f'delete service: {service_name} nG1 API request failed')
            logger.error(f'Response Code: {resp.status_code}. Response Body: {resp.text}.')
            return False
    except Exception: # Handle other unexpected errors.
        logger.exception(f'delete service: {service_name} nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False

def update_service(session, config_data, service_name, logger):
    """Use the nG1 API to update a network service.
    :session: An instance of the ApiSession class that holds all our API session params.
    :config_data: A dict that holds the service configuration parameters.
    :service_name: The name of the service. Used for success or failure log posting.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/services"
    url = session.ng1_host + uri
    try:
        # use json.dumps to provide a serialized json object (a string actually).
        # this json_string will become our new configuration for this service_name.
        json_string = json.dumps(config_data)
        # perform the HTTPS API post to and pass in the serialized json object config_data
        put = requests.put(url, headers=session.headers, data=json_string, verify=False, cookies=session.cookies)

        if put.status_code == 200: # success
            logger.info(f'update service: {service_name} nG1 API PUT Successful')
            return True
        else: # Update Service has failed.
            logger.error(f'update service: {service_name} nG1 API request failed')
            logger.error(f'Response Code: {put.status_code}. Response Body: {put.text}.')
            return False
    except Exception: # Handle other unexpected errors.
        logger.exception(f'update service: {service_name} nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False

def get_domains(session, logger):
    """Use the nG1 API to get the current domains.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the domain hierarchy info as a dict.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/domains"
    url = session.ng1_host + uri

    try:
        # perform the HTTPS API call to get the current domain hierarchy configuration
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)
        if get.status_code == 200:
            # success
            logger.info(f'get domains nG1 API request Successful')
            domain_data=json.loads(get.text)
            return True, domain_data
        elif get.status_code == 404:
            # No domains were found
            logger.info(f'get domains nG1 API request Successful')
            logger.info(f'No domains were found in the nG1 config')
            return True, None
        else:
            logger.error(f'get domains nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get domains nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def get_domain_detail(session, domain_name, logger):
    """Use the nG1 API to get the attributes of a specific domain.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the domain_detail_data as a dict.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/domains/" + domain_name
    url = session.ng1_host + uri

    try:
        # perform the HTTPS API call to get the domain detail attributes
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)
        if get.status_code == 200:
            # success
            logger.info(f'get domain detail for: {domain_name} nG1 API request Successful')
            domain_detail_data=json.loads(get.text)
            return True, domain_detail_data
        elif get.status_code == 404:
            # The specific domain_name was not found
            logger.info(f'get domain detail for: {domain_name} nG1 API request Successful')
            logger.info(f'No domain for {domain_name} was found in the nG1 config')
            return True, None
        else:
            logger.error(f'get domain detail for: {domain_name} nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get domain detail for: {domain_name} nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None


def verify_wan_domain(session, domain_data, logger):
    """Use the nG1 API to get the id of the WAN domain.
    If it does not exist, create it under the root 'Enterprise' domain.
    :session: An instance of the ApiSession class that holds all our API session params.
    :domain_data: The current domain hierarchy as a dict
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return status = True and the id of the WAN domain.
    Return status = False and None if there are any errors or exceptions.
    """

    try:
        for domain in domain_data['domain']:
            if domain['serviceName'] == 'WAN':
                return True, domain['id']
        logger.info('WAN domain not found, creating WAN domain...')
        domains_dict={}
        domain_ary=[]
        domain_dict={}
        #domain_members_ary=[]
        #domain_member_dict={}
        domain_dict['domainName'] = 'WAN'
        domain_dict['id'] = '-1'
        domain_dict['parentID'] = 1
        #domain_member_dict['enableAlert']= False
        #domain_members_ary.append(domain_member_dict.copy())
        #domain_dict['domainMembers']=domain_members_ary
        domain_ary.append(domain_dict.copy())
        domains_dict['domainDetail'] = domain_ary
        domain_name = domain_dict['domainName']
        #print('\ndomains_dict is:')
        #pprint.pprint(domains_dict)
        status = create_domain(session, domains_dict, domain_name, logger)
        if status == False: # the create_domain operation has failed Exit.
            logger.error(f'Create domain {domain_name} has failed')
            return False, None
        else:
            status, domain_detail_data = get_domain_detail(session, domain_name, logger)
            if status == True and domain_detail_data == None: # We did not create a WAN domainName
                logger.error(f'get_domain_detail for: {domain_name} has failed')
                logger.error(f'Domain: {domain_name} was not found in the domain hierarchy')
                return False, None
            elif status == False:
                logger.error(f'get_domain_detail for: {domain_name} has failed')
                return False, None
            else:
                return True, domain_detail_data['domainDetail'][0]['id']

    except Exception: # Handle other unexpected errors.
        logger.exception(f'verify_wan_domain failed')
        return False, None


def create_domain(session, config_data, domain_name, logger):
    """Use the nG1 API to create a domain.
    :session: An instance of the ApiSession class that holds all our API session params.
    :config_data: A dict that holds the domain configuration parameters.
    :domain_name: The name of the domain. Used for success or failure log posting.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/domains"
    url = session.ng1_host + uri
    try:
        # use json.dumps to provide a serialized json object (a string actually).
        # this json_string will become our new configuration for this domain.
        json_string = json.dumps(config_data)
        # perform the HTTPS API post to and pass in the serialized json object config_data
        post = requests.post(url, headers=session.headers, data=json_string, verify=False, cookies=session.cookies)

        if post.status_code == 200: # success
            logger.info(f'create domain: {domain_name} nG1 API POST Successful')
            return True
        else: # Create domain has failed.
            # If the domain exists, don't post an error message, just show as info.
            if 'exists' in post.text:
                logger.info(f'create domain: {domain_name} already exists')
                return True
            else:
                logger.error(f'create domain: {domain_name} nG1 API request failed')
                logger.error(f'Response Code: {post.status_code}. Response Body: {post.text}.')
                return False
    except Exception: # Handle other unexpected errors.
        logger.exception(f'create domain: {domain_name} nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False

def modify_domain(session, config_data, domain_name, logger):
    """Use the nG1 API to modify a domain. Most likely to add or remove domain members.
    :session: An instance of the ApiSession class that holds all our API session params.
    :config_data: A dict that holds the domain configuration parameters.
    :domain_name: The name of the domain. Used for success or failure log posting.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/domains"
    url = session.ng1_host + uri
    try:
        # use json.dumps to provide a serialized json object (a string actually).
        # this json_string will be used to modify our configuration for this domain.
        json_string = json.dumps(config_data)
        # perform the HTTPS API put and pass in the serialized json object config_data
        put = requests.put(url, headers=session.headers, data=json_string, verify=False, cookies=session.cookies)

        if put.status_code == 200: # success
            logger.info(f'Modify domain: {domain_name} nG1 API POST Successful')
            return True
        else: # Modify domain has failed.
            logger.error(f'Modify domain: {domain_name} nG1 API request failed')
            logger.error(f'Response Code: {put.status_code}. Response Body: {put.text}.')
            return False
    except Exception: # Handle other unexpected errors.
        logger.exception(f'Modify domain: {domain_name} nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False


def create_domains(session, intersection_df, wan_domain_id, new_MIBII_network_service_names, logger):
    """Use the nG1 API to create the domain tree for any new network services that were created.
    There are three domain levels under Enterprise; WAN, organization and region. The region
    domain contains the new or modified network services as members.
    :session: An instance of the ApiSession class that holds all our API session params.
    :intersection_df: A Pandas dataframe that holds the info needed to build up the domain configuration.
    :wan_domain_id: The id number of the "WAN" domain so we can reference that as a parentID number.
    :new_MIBII_network_service_names: A list of new network service names that don't already exist.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    try:
        NewServicesDF = pd.DataFrame() # Initialize an empty dataframe to append new network service data in.
        for new_MIBII_network_service_name in new_MIBII_network_service_names: # Loopt through the new service names list.
            tempDF = intersection_df.loc[intersection_df.netServiceName == new_MIBII_network_service_name]
            #print('\ntempDF data is:')
            #print(tempDF)
            NewServicesDF = pd.concat([NewServicesDF,tempDF])
        # print('\nNewServicesDF data is:')
        # print(NewServicesDF)
        for index, row in NewServicesDF.iterrows():
            corpscada_type = row['CorpSCADA_Type']
            if corpscada_type == 'Corporate':
                corpscada_type = 'Corp' # This corpscada_type gets abbreviated.
            region = row['LOB']
            if region == 'Corporate': # Handle case where org and region have the same name.
                region = 'Corp'
            mlob = row['MLOB']
            network_service_name = row['netServiceName']
            network_service_id = row['netServiceID']
            if mlob == 'CORE': # Handle case where corpscada_type is not used.
                organization = 'CORE-Network_Services'
            elif mlob == 'CORPORATE': # Handle case where corpscada_type is not used.
                organization = 'CORPORATE'
            elif mlob == 'POWER_STORAGE': # Handle case where corpscada_type is not used.
                organization == 'POWER_STORAGE'
            else:
                organization = mlob + '-' + corpscada_type

            domains_dict={}
            domain_ary=[]
            domain_dict={}
            domain_dict['domainName'] = organization
            domain_dict['id'] = '-1'
            domain_dict['parentID'] = wan_domain_id
            domain_ary.append(domain_dict.copy())
            domains_dict['domainDetail'] = domain_ary
            domain_name = organization
            #print('\norganization_domains_dict is:')
            #pprint.pprint(domains_dict)

            # Check to see if the organization domain already exists.
            status, org_domain_detail_data = get_domain_detail(session, domain_name, logger)
            if status == True and org_domain_detail_data != None: # The domain already exists.
                logger.info(f'Organization domain: {domain_name} already exists')
                parentID = org_domain_detail_data['domainDetail'][0]['id']
            elif status == False:
                logger.error(f'get_domain_detail for: {domain_name} has failed')
                return False
            else: # Create the organization domain
                status = create_domain(session, domains_dict, domain_name, logger)
                if status == False: # the create_domain operation has failed Exit.
                    logger.error(f'Create organization domain {domain_name} has failed')
                    return False
                # We need to get the ID of the new organization domain so we can use it as a parentID number.
                status, org_domain_detail_data = get_domain_detail(session, domain_name, logger)
                if status == True and org_domain_detail_data == None: # We did not create the domain
                    logger.error(f'Organization domain: {domain_name} was not found in the domain hierarchy as expected')
                    return False
                elif status == False:
                    logger.error(f'get_domain_detail for organization domain: {domain_name} has failed')
                    return False
                else:
                    parentID = org_domain_detail_data['domainDetail'][0]['id']

            # Build the definition for the region domain.
            # The new network service will be a domain Member.
            domains_dict={}
            domain_ary=[]
            domain_dict={}
            domain_members_ary=[]
            domain_member_dict={}
            domain_dict['domainName'] = region
            domain_dict['id'] = '-1'
            domain_dict['parentID'] = parentID
            domain_member_dict['enableAlert'] = True
            domain_member_dict['serviceName'] = network_service_name
            domain_member_dict['id'] = network_service_id
            domain_members_ary.append(domain_member_dict.copy())
            domain_dict['domainMembers'] = domain_members_ary
            domain_ary.append(domain_dict.copy())
            domains_dict['domainDetail'] = domain_ary
            domain_name = region
            #print('\nregion_domains_dict is:')
            #pprint.pprint(domains_dict)

            # Check to see if the region domain already exists.
            region_domain_exists = False
            status, region_domain_detail_data = get_domain_detail(session, domain_name, logger)
            # print('\nregion_domain_detail_data is:')
            # pprint.pprint(region_domain_detail_data)
            if status == True and region_domain_detail_data != None: # The domain already exists.
                logger.info(f'Region domain: {domain_name} already exists')
                # Set the region domain ID number to that of the existing region domain.
                domain_dict['id'] = region_domain_detail_data['domainDetail'][0]['id']
                region_domain_exists = True
            elif status == False:
                logger.error(f'get_domain_detail for: {domain_name} has failed')
                return False
            if region_domain_exists == False: # Create the region domain with the new network service as a member.
                status = create_domain(session, domains_dict, domain_name, logger)
                if status == False: # the create_domain operation has failed Exit.
                    logger.error(f'Create domain {domain_name} has failed')
                    return False
            else: # Check to see if this new network service is already a member of the region domain.
                domain_member_exists = False
                # Check to see if there are no domainMembers at all for this region.
                if 'domainMembers' not in region_domain_detail_data['domainDetail'][0]:
                    region_domain_detail_data['domainDetail'][0]['domainMembers'] = [] # Set domainMembers to an empty list of dicts.
                    domain_member_exists = False
                else: # Interate through the domainMembers and see if this serviceName is already there.
                    domainMembers_list = region_domain_detail_data['domainDetail'][0]['domainMembers']
                    for domain_member in domainMembers_list:
                        if domain_member['serviceName'] == network_service_name:
                            domain_member_exists = True
                if domain_member_exists == False: # We need to add the new network service as a region domain member.
                    logger.info(f'network service: {network_service_name} is not yet a member of region domain: {domain_name}, adding member...')
                    region_domain_detail_data['domainDetail'][0]['domainMembers'].append(domain_member_dict.copy())
                    # print('\nregion_domain_detail_data is:')
                    # pprint.pprint(region_domain_detail_data)
                    status = modify_domain(session, region_domain_detail_data, domain_name, logger)
                    if status == False: # the modify_domain operation has failed Exit.
                        logger.error(f'Modify domain {domain_name} has failed')
                        return False
                else:
                    logger.info(f'network service: {network_service_name} is already a member of region domain: {domain_name}, no modification made')

        return True
    except Exception: # Handle other unexpected errors.
        logger.exception(f'An exception has occurred in create_domains')
        return False

# -----------------------------------------------------------------------------------------------------------------
def main():
    prog_version = '0.4-alpha'
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.

    # Create a logger instance and write the starting date_time to a log file.
    log_filename = 'TC_devices_sync_' + date_time + '.log' #The name of the log file we will write to.
    logger = create_logging_function(log_filename)
    if logger == False: # Creating the logger instance has failed. Exit.
        print("\n[CRITICAL] Main, Creating the logger instance has failed")
        print('Exiting...')
        sys.exit(1)

    status, is_set_config_true = flags_and_arguments(prog_version, logger)
    if status == False: # Parsing the run command flags or arguments has failed Exit.
        logger.info("\nMain, Parsing the run command arguments has failed")
        print('Exiting...')
        sys.exit(1)

    # Hardcoding the name of the nG1 device interfaces "current" CSV file that holds the config data queried from the nG1 API.
    device_interfaces_config_current_filename = 'device_interfaces_config_current.csv' # This file will get overwritten by design if the same config_type is run again.
    # Hardcoding the output filename that holds a list of names of the network services candidates for deletion.
    net_srv_delete_candidates_filename = 'net_srv_delete_candidates.csv'
    # Hardcoding the output filename that holds a list of names of the network services candidates for addition.
    net_srv_add_candidates_filename = 'net_srv_add_candidates.csv'
    # Hardcoding the name of the "current" CSV file that holds the config data exported from Solarwinds.
    solarwinds_filename = 'solarwinds_config_current.csv' # This file will get overwritten by design if the same config_type is run again.
    # Hardcoding the name of the CSV file that holds the intersection of MIB II device interface configurations as matched by IP address.
    solarwinds_archive_filename = 'solarwinds_config_archive' # No extention as we will append a time-date + .csv to the name.
    # Hardcoding the name of the "archive" CSV file that we will use to backup the "current" Solarwinds CSV file.
    devices_intersection_filename = 'devices_intersection.csv'
    # Hardcoding the name of the "change_log" CSV file that we will use to output and differences seen since last program execution.
    solarwinds_change_log_csv = 'solarwinds_change_log.csv' # This file will get overwritten by design.
    # Hardcoding the filenames for encrypted credentials and the key file needed to decrypt the credentials.
    cred_filename = 'CredFile.ini'
    # Hardcoding the filename for the list of provider names. This is optional. If not found a static default list will be used.
    provider_list_filename = 'provider_list.txt'
    # Hardcoding the filename for the list of possible WAN interface types. This is optional. If not found a static default list will be used.
    interface_type_list_filename = 'interface_type_list.txt'

    os_type = sys.platform
    if os_type == 'linux':
        ng1key_file = '.ng1key.key' # hide the probekey file if Linux.
    else:
        ng1key_file = 'ng1key.key' # don't hide it if Windows.

    # Get the user's credentials from a file and decrypt them.
    creds = get_decrypted_credentials(cred_filename, ng1key_file, logger)
    if creds == False: # Creating the creds instance has failed. Exit.
        logger.critical(f"Main, Getting the nG1 login credentials from file: {cred_filename} failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # Based on what is in the creds, determine all the parameters needed to make an nG1 API connection.
    status, session = determine_ng1_api_params(creds, logger)
    if status == False: # Determining the nG1 API parameters has failed. Exit.
        logger.critical(f"Main, determining the nG1 API parameters has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # Open an API session to nG1 and keep it open for all subsequent calls.
    status = open_session(session, logger)
    if status == False: # Opening the HTTP-HTTPS nG1 API session has failed. Exit.
        logger.critical(f"Main, opening the HTTP-HTTPS nG1 API session has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # Get the list of provider names either from a local file or from a static default list.
    status, provider_list = get_provider_list(provider_list_filename, logger)
    if status == False: # Getting the list of provider names has failed. Exit.
        logger.critical(f"Main, get_provider_list has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # Get the list of WAN interface types either from a local file or from a static default list.
    status, interface_type_list = get_interface_type_list(interface_type_list_filename, logger)
    if status == False: # Getting the list of interface types has failed. Exit.
        logger.critical(f"Main, get_interface_type_list has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # Get all the Active or Inactive MIB II devices currently configured in nG1.
    status, devices_config_data = get_devices(session, logger)
    if status == False: # get_devices has failed. Exit.
        logger.critical(f"Main, get_devices has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    #print("\nMain: devices_config_data is: ")
    #pprint.pprint(devices_config_data)

    # For each MIB II device in nG1, append the WAN interfaces to the devices_config_data dict.
    status, devices_config_data = get_device_wan_interfaces(devices_config_data, interface_type_list, provider_list, session, logger)
    if status == False: # Getting the MIBII device WAN interfaces has failed.
        logger.critical(f"Main, get_device_wan_interfaces has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)
    elif devices_config_data == {'deviceConfigurations': []}:
        logger.info(f"Main, get_device_wan_interfaces successful")
        logger.info(f"Main, No WAN interfaces were found for MIBII devices")
        print('Nothing to do. Exiting...')
        sys.exit(0)

    #print("\nMain2: devices_config_data is: ")
    #pprint.pprint(devices_config_data)

    # print("devices_config_data is: ")
    # pprint.pprint(devices_config_data)

    # For each MIB II device in nG1, get the WAN speed of the only Active WAN interface.
    # Add the WAN speed as an attribute to the nG1 devices_config_data.
    #status, devices_config_data = get_device_wan_speeds(devices_config_data, session, logger)
    #if status == False: # Getting the interface wan speeds has failed.
        #logger.critical(f"Main, get_device_wan_speeds has failed")
        #logger.info(f"\nMain, get_device_wan_speeds has failed")
        #print(f'Check the log file: {log_filename}. Exiting...')
        #sys.exit(1)

   # print("devices_config_data is: ")
   # pprint.pprint(devices_config_data)

    config_type = 'devices'
    status, ng1_devices_df = convert_json_dict_to_dataframe(devices_config_data, config_type, logger)
    if status == False: # The conversion has failed. Exit.
        logger.critical(f"Main, dataframe conversion has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    #print('ng1_devices_df is:')
    #print(ng1_devices_df)

    # Backup the current configuration CSV created the last time this program ran (rename it if it exists).
    #status, config_current_is_found, current_df = backup_current_CSV(solarwinds_filename, solarwinds_archive_filename, logger)
    #if status == False: # Backing up the current CSV config file has failed.
        #logger.critical(f"Main, backup_current_csv has failed")
        #logger.info(f"\nMain, backup_current_csv has failed")
        #print(f'Check the log file: {log_filename}. Exiting...')
        #sys.exit(1)

    status = write_dataframe_to_csv(ng1_devices_df, device_interfaces_config_current_filename, logger)
    if status == False: # The write dataframe to CSV file operation has failed. Exit.
        logger.critical(f"Main, write_dataframe_to_csv to CSV file: {device_interfaces_config_current_filename} has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    status, solarwinds_current_df = convert_current_solarwinds_CSV_to_dataframe(solarwinds_filename, logger)
    if status == False: # Conversion of current solarwinds CSV to a pandas dataframe has failed.
        logger.critical(f"Main, convert_current_solarwinds_CSV_to_dataframe has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    status, intersection_df = find_intersection_solarwinds_to_current_device_interfaces(solarwinds_current_df, ng1_devices_df, logger)
    if status == False: # The write dataframe to CSV file operation has failed. Exit.
        logger.critical(f"Main, find_intersection_solarwinds_to_current_device_interfaces has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    status = write_dataframe_to_csv(intersection_df, devices_intersection_filename, logger)
    if status == False: # The write dataframe to CSV file operation has failed. Exit.
        logger.critical(f"Main, write_dataframe_to_csv to CSV file: {devices_intersection_filename} has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    MIBII_network_services = []
    status, current_network_services_data = get_services(session, logger)
    if status == False: # The get services nG1 API call has failed. Exit.
        logger.critical(f"Main, get_services has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)
    elif status == True and current_network_services_data == None: #No network services exist yet.
        logger.info('No network services of any kind exist in the nG1 configuration currently')
    else:
        # Some network services currently exist in the nG1 configuration.
        # Filter the list of network services to just a list of service names that include those with '_MIB Polling' in the name.
        for network_service in current_network_services_data['service']:
            if network_service['serviceName'].endswith('_MIB Polling'): # Filter on just net services for MIBII.
                MIBII_network_services.append(network_service['serviceName'])
        # print('\nMIBII_network_services are: ')
        # pprint.pprint(MIBII_network_services)
        if MIBII_network_services == None:
            logger.info('No MIBII network services exist in the nG1 configuration currently')

    status, alert_profiles_data = get_service_alert_profiles(session, logger)
    if status == False: # The get alert profiles nG1 API call has failed. Exit.
        logger.critical(f"Main, get_service_alert_profiles has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)
    elif status == True and alert_profiles_data == None: #No service alert profiles exist yet.
        logger.critical(f"Main, No service alert profiles exist in nG1")
        print(f'Check the nG1 for valid service alert profiles. Exiting...')
        sys.exit(1)
    else:
       # print('\nalert_profiles_data is: ')
       # pprint.pprint(alert_profiles_data)
       pass

    status, alert_profile_ids_dict = create_alert_profile_ids_dict(alert_profiles_data, logger)
    if status == False: # The create_alert_profile_ids_dict has failed. Exit.
        logger.critical(f"Main, create_alert_profile_ids_dict has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    status, intersection_df = add_alert_profile_ids(intersection_df, alert_profile_ids_dict, logger)
    if status == False: # The add alert profile id number opertation failed. Exit.
        logger.critical(f"Main, add_alert_profile_ids has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    #print(f"\nThe updated intersection_df with alert profile IDs is:")
    #pprint.pprint(intersection_df)

    status, intersection_df, valid_MIBII_network_service_names, new_MIBII_network_service_names = create_network_service_configs(session, is_set_config_true, MIBII_network_services, net_srv_add_candidates_filename, intersection_df, logger)
    if status == False: # The create_network_service_configs operation has failed. Exit.
        logger.critical(f"Main, create_network_service_configs has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)
    if status == None: # There are no new WAN interfaces to add and none to modify.
        logger.info("Main, There are no new WAN interfaces to add and none to modify.")
        add_or_modify = False # Set flag that there are no additions or modifications to make.
    else:
        add_or_modify = True # Set flag that there are some additions or modifications to make.

    #print('\nvalid_MIBII_network_service_names are: ')
    #pprint.pprint(valid_MIBII_network_service_names)

    #print('\nMIBII_network_services are: ')
    #pprint.pprint(MIBII_network_services)

    if MIBII_network_services != None and valid_MIBII_network_service_names != None:
        status = delete_orphan_services(session, is_set_config_true, MIBII_network_services, valid_MIBII_network_service_names, net_srv_delete_candidates_filename, logger)
        if status == False: # The delete_orphan_services operation has failed. Exit.
            logger.critical(f"Main, delete_orphan_services operation has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit(1)

    if  is_set_config_true == False: # No --set flag was specified at launch time.
        logger.info("Main, Data collection completed.")
        logger.info("Main, No modifications will be made as --set flag was not specified")

    # Only do domin mods if there are additions of MIBII network services and
    # the user specified the --set flag.
    if add_or_modify == True and is_set_config_true == True: #
        status, current_domains = get_domains(session, logger)
        if status == False: # The get_current_domains has failed. Exit.
            logger.critical(f"Main, get_domains has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit(1)

        #print(f"\nThe current domains are:")
        #pprint.pprint(current_domains)

        status, wan_domain_id = verify_wan_domain(session, current_domains, logger)
        if status == False: # The verify_wan_domain has failed. Exit.
            logger.critical(f"Main, verify_wan_domain has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit(1)

        #print(f'\nThe WAN domain id is: {wan_domain_id}')

        status = create_domains(session, intersection_df, wan_domain_id, new_MIBII_network_service_names, logger)
        if status == False: # The create_domains operation has failed. Exit.
            logger.critical(f"Main, create_domains has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit(1)

    # We are all finished, close the nG1 API session.
    if close_session(session, logger) == False: # Failed to close the API session.
        logger.critical(f"Main, close_session has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    #logger.info(f'The CSV file: {config_current_csv} was created at {time.ctime()}')
    logger.info('Program execution has completed Successfully')
    sys.exit(0)

if __name__ == "__main__":
    main()
