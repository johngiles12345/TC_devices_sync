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

__version__ = "0.1"
__status__ = "beta"
__author__ = "John Giles"
__date__ = "2021 May 28th"
__env__= "Windows/Linux"
__Language__ = "Python v3"

# Disable the warnings for ignoring Self-Signed Certificates
requests.packages.urllib3.disable_warnings()

class ng1_device():

    def __init__(self, deviceName, deviceIPAddress, status, deviceType, activeInterfaces, version):
        self.deviceName = deviceName
        self.deviceIPAddress = deviceIPAddress
        self.status = status
        self.deviceType = deviceType
        self.activeInterfaces = activeInterfaces
        self.version = version

    def get_descriptions(self, seperator):
        return self.deviceName + seperator + self.deviceIPAddress + seperator + self.status + seperator + self.deviceType + seperator + str(self.activeInterfaces) + seperator + self.version

    def get_items(self, seperator):
        return 'deviceName' + seperator + 'deviceIPAddress' + seperator + 'status' + seperator + 'deviceType' + seperator + 'activeInterfaces' + seperator + 'version'

class ng1_interface():

    def __init__(self, deviceName, deviceIPAddress, interfaceName, interfaceNumber, interfaceSpeed, interfaceLinkType, status):
        self.deviceName = str(deviceName)
        self.deviceIPAddress = str(deviceIPAddress)
        self.interfaceName = str(interfaceName)
        self.interfaceNumber = str(interfaceNumber)
        self.interfaceSpeed = str(interfaceSpeed)
        self.interfaceLinkType = str(interfaceLinkType)
        self.status = str(status)

    def get_descriptions(self, seperator):
        return self.deviceName + seperator + self.deviceIPAddress + seperator + self.interfaceName + seperator + str(self.interfaceNumber) + seperator + self.interfaceSpeed + seperator + self.interfaceLinkType + seperator + self.status

    def get_items(self, seperator):
        return 'deviceName' + seperator + 'deviceIPAddress' + seperator + 'interfaceName' + seperator + 'interfaceNumber' + seperator + 'interfaceSpeed' + seperator + 'interfaceLinkType' + seperator + 'status'

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
    the current Solarwinds config. Then it will merge the required columns and produce a config CSV file.
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
        parser.add_argument('--set', '-s', action="store_true", help='set the nGeniusONE config to match the solarwindd_config_current.csv', dest='set', default=False)
        parser.add_argument('--version', '-v', action="store_true", help="show program version and exit", dest='version', default=False)
        # Parse the arguments and create a result.
        args = parser.parse_args()
        if args.version == True: # They typed either "-v" or "--version" flags.
            print(f'Program version is: {prog_version}')
            sys.exit()
        if args.set == True: # They typed either "-s" or "--set" flags.
            is_set_config_true = True # I need to do both a get and a set operation.
        else:
            is_set_config_true = False # I only need to do a get operation.

        return True, is_set_config_true
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] Parsing the run command arguments has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
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

def get_devices(session, logger):
    """Use the nG1 API to get the current device configuration in the system.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return stauts = True and the the devices object.
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
            #print('MIB II Devices: ')
            #print('No.: deviceName\tdeviceIPAddress\tstatus\tdeviceType\tactiveInterfaces\tversion')
            # return the json object that contains the site information
            #return get.json()
            json_data=json.loads(get.text)
            devices_count=len(json_data['deviceConfigurations'])
            devices=[]
            for i in range(devices_count):
                if json_data['deviceConfigurations'][i]['deviceType'] == 'Router/Switch':
                    json_data['deviceConfigurations'][i]['version'] = "N/A"
                    device=ng1_device(json_data['deviceConfigurations'][i]['deviceName'],
                    json_data['deviceConfigurations'][i]['deviceIPAddress'], json_data['deviceConfigurations'][i]['status'],
                    json_data['deviceConfigurations'][i]['deviceType'], json_data['deviceConfigurations'][i]['activeInterfaces'],
                    json_data['deviceConfigurations'][i]['version'])
                    devices.append(device)
                    #print(str(i+1) + ': ' + device.get_descriptions('\t'))
            return True, devices
        else:
            logger.error(f'get devices nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get devices nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def get_interfaces(device, session, logger):

    """Use the nG1 API to get the current interface configuration for each device in the system.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return the interfaces info in JSON format. Return status = True.
    Return status = False and None if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/devices/" + device.deviceName + "/interfaces"
    url = session.ng1_host + uri

    try:
        # perform the HTTPS API call to get the devices information
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)

        if get.status_code == 200:
            # success
            logger.info(f'get interfaces for {device.deviceName} nG1 API request Successful')
            interfaces=[]
            #print('MIB II Device Interfaces: ')
            #print('No.: deviceName\tinterfaceName\tinterfaceNumber\tinterfaceSpeed\tinterfaceLinkType\tstatus')
            json_data=json.loads(get.text)
            interfaceCount=len(json_data['interfaceConfigurations'])
            for i in range(interfaceCount):
                #print(f"\n{device.deviceType=}")
                if 'PFOS' in device.deviceType:
                    # Correct for bug in nG1 API
                    json_data['interfaceConfigurations'][i]['interfaceLinkType'] = json_data['interfaceConfigurations'][i]['portSpeed']
                elif 'Router/Switch' in device.deviceType:
                    # Correct for bug in nG1 API
                    json_data['interfaceConfigurations'][i]['interfaceLinkType'] = json_data['interfaceConfigurations'][i]['portSpeed']
                interface=ng1_interface(device.deviceName, device.deviceIPAddress, json_data['interfaceConfigurations'][i]['interfaceName'],
                json_data['interfaceConfigurations'][i]['interfaceNumber'], json_data['interfaceConfigurations'][i]['interfaceSpeed'],
                json_data['interfaceConfigurations'][i]['interfaceLinkType'], json_data['interfaceConfigurations'][i]['status'])
                interfaces.append(interface)
                #print(str(i+1) + ': ' + interface.get_descriptions('\t'))
                json_data['interfaceConfigurations'][i]['deviceName'] = device.deviceName
                json_data['interfaceConfigurations'][i]['deviceIPAddress'] = device.deviceIPAddress
            return True, json_data
            # return the json object that contains the site information
            #return get.json()
        else:
            logger.error(f'get interfaces nG1 API request failed.')
            logger.error(f'Response Code: {get.status_code}. Response Body: {get.text}.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get interfaces nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False, None

def get_domains(ng1_host, headers, cookies, logger): #ng1 cannot support json output, why?
    get_domains_uri = "/ng1api/ncm/domains"
    get_domains_url = ng1_host + get_domains_uri
    try:
        # perform the HTTPS API call
        get = requests.request("GET", get_domains_url, verify=False, cookies=cookies)

        if get.status_code == 200:
            # success
            logger.info('Get Domains Successfully.')

            #print('No.: deviceName\tdeviceIPAddress\tstatus\tdeviceType\tactiveInterfaces\tversion')
            #json_data=json.loads(get.text)
            #devices_count=len(json_data['deviceConfigurations'])
            domains=[]
            #for i in range(devices_count):
            #    device=ng1_device(json_data['deviceConfigurations'][i]['deviceName'], json_data['deviceConfigurations'][i]['deviceIPAddress'], json_data['deviceConfigurations'][i]['status'], json_data['deviceConfigurations'][i]['deviceType'], json_data['deviceConfigurations'][i]['activeInterfaces'], json_data['deviceConfigurations'][i]['version'])
            #    devices.append(device)
            #    print(str(i+1) + ': ' + device.get_descriptions('\t'))
            return True, domains
        else:
            logger.error('Get domains Failed. Response Code: ' + str(get.status_code) + '. Response Body: ' + get.text + '.')
            return False, None
    except Exception: # Handle other unexpected errors.
        logger.exception(f'get domains nG1 API request failed')
        logger.exception(f'URL sent is: {url}')
        return False

def get_domain_detail(session, domainName, logger): #ng1 cannot support json output, why?
    get_domain_uri = "/ng1api/ncm/domains/" + domainName
    get_domain_url = ng1_host + get_domain_uri
    # perform the HTTPS API call
    #get = requests.request("GET", get_domain_url, headers=headers, verify=False, cookies=cookies)
    get = requests.request("GET", get_domain_url, verify=False, cookies=cookies)

    if get.status_code == 200:
        # success
        logger.info('Get Domain Detail Successfully.')
        logger.info('Response Code: ' + str(get.status_code))
        logger.info('Response Body: ' + get.text)
        #print('No.: deviceName\tdeviceIPAddress\tstatus\tdeviceType\tactiveInterfaces\tversion')
        #json_data=json.loads(get.text)
        #devices_count=len(json_data['deviceConfigurations'])
        #devices=[]
        #for i in range(devices_count):
        #    device=ng1_device(json_data['deviceConfigurations'][i]['deviceName'], json_data['deviceConfigurations'][i]['deviceIPAddress'], json_data['deviceConfigurations'][i]['status'], json_data['deviceConfigurations'][i]['deviceType'], json_data['deviceConfigurations'][i]['activeInterfaces'], json_data['deviceConfigurations'][i]['version'])
        #    devices.append(device)
        #    print(str(i+1) + ': ' + device.get_descriptions('\t'))
        return True
    else:
        logger.error('Get Domain Detail Failed. Response Code: ' + str(get.status_code) + '. Response Body: ' + get.text + '.')
        return False

def post_domain(domain, ng1_host, headers, cookies, logger):
    post_domain_uri = "/ng1api/ncm/domains/"
    post_domain_url = ng1_host + post_domain_uri
    # perform the HTTPS API call
    post = requests.request("POST", post_domain_url, data=json.dumps(domain), headers=headers, verify=False, cookies=cookies)

    if post.status_code == 200:
        # success
        logger.info('Post Domain Successfully.')
        logger.info('Response Code: ' + str(post.status_code))
        logger.info('Response Body: ' + post.text)
        json_data=json.loads(post.text)
        domainName=json_data['domainDetail'][0]['domainName']
        domainID=json_data['domainDetail'][0]['id']
        print('The ID of Domain [' + domainName + '] is: ' + str(domainID))
        return True, domainID
    else:
        logger.error('Post Domain Failed. Response Code: ' + str(post.status_code) + '. Response Body: ' + post.text + '.')
        return False, None

def get_service(serviceName, ng1_host, headers, cookies, logger):
    get_service_uri = "/ng1api/ncm/services/" + serviceName
    get_service_url = ng1_host + get_service_uri
    # perform the HTTPS API call
    get = requests.request("GET", get_service_url, headers=headers, verify=False, cookies=cookies)

    if get.status_code == 200:
        # success
        logger.info('Get Service Successfully.')
        logger.info('Response Code: ' + str(get.status_code))
        logger.info('Response Body: ' + get.text)
        json_data=json.loads(get.text)
        serviceType=json_data['serviceDetail'][0]['serviceType']
        serviceID=json_data['serviceDetail'][0]['id']
        serviceName=json_data['serviceDetail'][0]['serviceName']
        membersCount=len(json_data['serviceDetail'][0]['serviceMembers'])
        if serviceType == 1:
            serviceTypeStr = 'Application'
        elif serviceType == 6:
            serviceTypeStr = 'Network'
        else:
            serviceTypeStr = 'Others'
        print('The type of ' + serviceName + ' is ' + serviceTypeStr + '; ID = ' +  serviceID + '; It has ' + str(membersCount) + ' members.')
        return True
    else:
        logger.error('Get Service Failed. Response Code: ' + str(get.status_code) + '. Response Body: ' + get.text + '.')
        return False

def post_service(service, ng1_host, headers, cookies, logger):

    post_service_uri = "/ng1api/ncm/services"
    post_service_url = ng1_host + post_service_uri
    post = requests.request("POST", post_service_url, data=json.dumps(service), headers=headers, verify=False, cookies=cookies)

    if post.status_code == 200:
        # success
        logger.info('Post Service Successfully.')
        logger.info('Response Code: ' + str(post.status_code))
        logger.info('Response Body: ' + post.text)
        json_data=json.loads(post.text)
        serviceName=json_data['serviceDetail'][0]['serviceName']
        serviceID=json_data['serviceDetail'][0]['id']
        return True, serviceName
    else:
        logger.error('Post Service Failed. Response Code: ' + str(post.status_code) + '. Response Body: ' + post.text + '.')
        return False, None

def post_service_into_domain(domembers, domainName, ng1_host, headers, cookies, logger):

    post_domembers_uri = "/ng1api/ncm/domains/" + domainName + '/members'
    post_domembers_url = ng1_host + post_domembers_uri
    post = requests.request("POST", post_domembers_url, data=json.dumps(domembers), headers=headers, verify=False, cookies=cookies)

    if post.status_code == 200:
        # success
        logger.info('Post Service into Domain Successfully.')
        logger.info('Response Code: ' + str(post.status_code))
        logger.info('Response Body: ' + post.text)
        json_data=json.loads(post.text)
        return True
    else:
        logger.error('Post Service into Domain Failed. Response Code: ' + str(post.status_code) + '. Response Body: ' + post.text + '.')
        return False

def demo_Add_Domain_into_Level1(session, domainName, logger):

    # Add a Domain into level 1
    ''' Sample
    domains = {
            "domainDetail":[
                {
                    "userList": "ADMINISTRATOR"
                    "domainName": "myDomain",
                    "id": -1,
                    "parentID": 1
                }
            ]
        }
    '''
    #domainName=input('domainName: ')
    domains_dict={}
    domain_ary=[]
    domain_dict={}

    domain_dict['userList']='ADMINISTRATOR'
    domain_dict['domainName']=domainName
    domain_dict['id']=-1
    domain_dict['parentID']=1
    domain_ary.append(domain_dict.copy())
    domains_dict['domainDetail']=domain_ary

    print('The data to be posted is : ')
    print(domains_dict)

    post_domain_status, domainID = post_domain(domains_dict, ng1_host, headers, cookies, logger)


def demo_Add_Domain_into_Level2(session, logger):
    # Open a session to nG1 and resuse this session for all our API calls.
    cookies = open_session(ng1_host, ng1_username, ng1_password, headers, logger)
    if cookies is None: # Opening the session to ng1 has failed. Exit.
        return

    # Add a Domain into level 1 and if exist, it will return the Domian ID
    ''' Sample
    domains = {
            "domainDetail":[
                {
                    "userList": "ADMINISTRATOR"
                    "domainName": "myDomain",
                    "id": -1,
                    "parentID": 1
                }
            ]
        }
    '''
    domainNameL1=input('Level 1 - domainName: ')
    domainNameL2=input('Level 2 - domainName: ')

    domainsL1_dict={}
    domainL1_ary=[]
    domainL1_dict={}

    domainL1_dict['userList']='ADMINISTRATOR'
    domainL1_dict['domainName']=domainNameL1
    domainL1_dict['id']=-1
    domainL1_dict['parentID']=1
    domainL1_ary.append(domainL1_dict.copy())
    domainsL1_dict['domainDetail']=domainL1_ary

    print('The data to be posted is : ')
    print(domainsL1_dict)

    post_domain_status, domainL1ID = post_domain(domainsL1_dict, ng1_host, headers, cookies, logger)

    if post_domain_status == True:
        domainsL2_dict={}
        domainL2_ary=[]
        domainL2_dict={}

        domainL2_dict['userList']='ADMINISTRATOR'
        domainL2_dict['domainName']=domainNameL2
        domainL2_dict['id']=-1
        domainL2_dict['parentID']=int(domainL1ID)
        domainL2_ary.append(domainL2_dict.copy())
        domainsL2_dict['domainDetail']=domainL2_ary

        print('The data to be posted is : ')
        print(domainsL2_dict)

        post_domain_status, domainL2ID = post_domain(domainsL2_dict, ng1_host, headers, cookies, logger)

    # Close the session to nG1.
    close_status = close_session(ng1_host, headers, cookies, logger)
    if close_status == False: # Closing the session to ng1 has failed. Exit.
        return
    else:
        # We are done. Exit anyway.
        return

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
            columns = ['Caption','IP_Address', 'CorpSCADA_Type', 'LOB', 'MLOB', 'Site']
            current_df = pd.read_csv(config_current_csv, sep='\t', usecols=columns, engine='python', encoding='utf-16')
            #current_df_mod = current_df.rename(columns={'IP_Address': 'deviceIPAddress'}, axis='columns')
            print("\nThe type of df that current_df is:")
            current_df.rename({'IP_Address': 'deviceIPAddress'}, axis=1, inplace=True)

            print(f'\nCurrent df is: \n{current_df}')
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
            #current_df = pd.read_csv(config_current_csv, encoding="ISO-8859–1")
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
    elif config_type == 'interfaces':
        column_headers = ['deviceName', 'deviceIPAddress', 'interfaceName', 'interfaceNumber', 'interfaceSpeed', 'interfaceLinkType', 'status']
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
    """Write the device and interface dataframe to a CSV file.
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
        intersection_df = pd.merge(solarwinds_current_df, right_now_df, how ='inner', on =['deviceIPAddress'])
        #intersection_df = solarwinds_current_df.merge(right_now_df, on=['deviceIPAddress']) # Compare the "current" dfright data to the "right now" dfleft data.
        print("\nintersection_df is:")
        print(intersection_df)
        return True, intersection_df
    except Exception:
        logger.exception(f'find_intersection_solarwinds_to_current_device_interfaces has failed"')
        return False, None




# -----------------------------------------------------------------------------------------------------------------
def main():
    prog_version = '0.0'
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
        logger.info("\nMain, Parsing the run command flags has failed")
        print('Exiting...')
        sys.exit(1)

    # Hardcoding the name of the nG1 device interfaces "current" CSV file that holds the config data queried from the nG1 API.
    device_interfaces_config_current_filename = 'device_interfaces_config_current.csv' # This file will get overwritten by design if the same config_type is run again.
    # Hardcoding the name of the "current" CSV file that holds the config data exported from Solarwinds.
    solarwinds_filename = 'solarwinds_config_current.csv' # This file will get overwritten by design if the same config_type is run again.
    # Hardcoding the name of the CSV file that holds the intersection of MIB II device interface configurations as matched by IP address.
    solarwinds_archive_filename = 'solarwinds_config_archive' # No extention as we will append a time-date + .csv to the name.
    # Hardcoding the name of the "archive" CSV file that we will use to backup the "current" Solarwinds CSV file.
    device_interfaces_intersection_filename = 'device_interfaces_intersection.csv'
    # Hardcoding the name of the "change_log" CSV file that we will use to output and differences seen since last program execution.
    solarwinds_change_log_csv = 'solarwinds_change_log.csv' # This file will get overwritten by design.
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
        logger.critical(f"Main, Getting the nG1 login credentials from file: {cred_filename} failed")
        logger.info(f"\nMain, Getting the ng1 login credentials from file: {cred_filename} failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # Based on what is in the creds, determine all the parameters needed to make an nG1 API connection.
    status, session = determine_ng1_api_params(creds, logger)
    if status == False: # Determining the nG1 API parameters has failed. Exit.
        logger.critical(f"Main, determining the nG1 API parameters has failed")
        logger.info(f"\nMain, determining the nG1 API parameters has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # Open an API session to nG1 and keep it open for all subsequent calls.
    status = open_session(session, logger)
    if status == False: # Opening the HTTP-HTTPS nG1 API session has failed. Exit.
        logger.critical(f"Main, opening the HTTP-HTTPS nG1 API session has failed")
        logger.info(f"\nMain, opening the HTTP-HTTPS nG1 API session has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # List all the devices
    status, devices_array = get_devices(session, logger)
    if status == False: # get_devices has failed. Exit.
        logger.critical(f"Main, get_devices has failed")
        logger.info(f"\nMain, get_devices has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)
    else:
        interface_df_list = []
        for device in devices_array:
            if device.status == 'Active' and device.deviceType == 'Router/Switch':
                status, current_interfaces_data = get_interfaces(device, session, logger)
                if status == False: # get_interfaces has failed. Exit.
                    logger.critical(f"Main, get_interfaces has failed")
                    logger.info(f"\nMain, get_interfaces has failed")
                    print(f'Check the log file: {log_filename}. Exiting...')
                    sys.exit(1)
                else:
                    # Convert the json nested dictionary to a flatend dataframe in pandas.
                    config_type = 'interfaces'
                    status, interface_df = convert_json_dict_to_dataframe(current_interfaces_data, config_type, logger)
                    interface_df_list.append(interface_df)
                    #print(f"right_now_df = \n{right_now_df}\n")
                    if status == False: # The conversion has failed. Exit.
                        logger.critical(f"Main, dataframe conversion has failed")
                        logger.info(f"\nMain, dataframe conversion has failed")
                        print(f'Check the log file: {log_filename}. Exiting...')
                        sys.exit(1)
        for interface_df in interface_df_list:
            print(f"\n{interface_df}")
        right_now_df = pd.concat(interface_df_list, ignore_index=True)
        print(f"\n{right_now_df}")


    # List all the domains
    #status, list_domains_ary = get_domains(ng1_host, headers, cookies, logger)

    # Get detail on a specific Domain
    #status = get_domain_detail(session, domainName, logger)

    #status = demo_Add_Domain_into_Level1(session, domainName, logger)

    #status = demo_Add_Domain_into_Level2(session, logger)

    #status = demo_Get_Service(session, logger)


    # Backup the current configuration CSV created the last time this program ran (rename it if it exists).
    #status, config_current_is_found, current_df = backup_current_CSV(solarwinds_filename, solarwinds_archive_filename, logger)
    #if status == False: # Backing up the current CSV config file has failed.
        #logger.critical(f"Main, backup_current_csv has failed")
        #logger.info(f"\nMain, backup_current_csv has failed")
        #print(f'Check the log file: {log_filename}. Exiting...')
        #sys.exit(1)

    status = write_dataframe_to_csv(right_now_df, device_interfaces_config_current_filename, logger)
    if status == False: # The write dataframe to CSV file operation has failed. Exit.
        logger.critical(f"Main, write_dataframe_to_csv to CSV file: {device_interfaces_config_current_filename} has failed")
        logger.info(f"\nMain, writing the dataframe to CSV file: {device_interfaces_config_current_filename} has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    #if config_current_is_found:
        #print(f"I found the {solarwinds_filename} file!!")
    status, solarwinds_current_df = convert_current_solarwinds_CSV_to_dataframe(solarwinds_filename, logger)
    if status == False: # Conversion of current solarwinds CSV to a pandas dataframe has failed.
        logger.critical(f"Main, convert_current_solarwinds_CSV_to_dataframe has failed")
        logger.info(f"\nMain, convert_current_solarwinds_CSV_to_dataframe has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    status, intersection_df = find_intersection_solarwinds_to_current_device_interfaces(solarwinds_current_df, right_now_df, logger)
    if status == False: # The write dataframe to CSV file operation has failed. Exit.
        logger.critical(f"Main, find_intersection_solarwinds_to_current_device_interfaces has failed")
        logger.info(f"\nMain, find_intersection_solarwinds_to_current_device_interfaces has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    status = write_dataframe_to_csv(intersection_df, device_interfaces_intersection_filename, logger)
    if status == False: # The write dataframe to CSV file operation has failed. Exit.
        logger.critical(f"Main, write_dataframe_to_csv to CSV file: {device_interfaces_intersection_filename} has failed")
        logger.info(f"\nMain, writing the dataframe to CSV file: {device_interfaces_intersection_filename} has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    # We are all finished, close the nG1 API session.
    if close_session(session, logger) == False: # Failed to close the API session.
        logger.critical(f"Main, close_session has failed")
        logger.info(f'\nMain, Unable to close the nG1 API session')
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit(1)

    #logger.info(f'The CSV file: {config_current_csv} was created at {time.ctime()}')
    logger.info('Program execution has completed Successfully')
    sys.exit(0)

if __name__ == "__main__":
    main()
