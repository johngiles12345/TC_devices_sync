from cryptography.fernet import Fernet
import ctypes
import time
import os
import sys
import getpass
import stdiomask

class Credentials():
    """
    This class creates a credentials object that holds all the attributes needed to connect to
    a NetScout nGeniusONE appliance or virtual appliance and authenticate.
    :return: An instance of this class with all parameters initialized.
    """
    def __init__(self):
        self.ng1hostname = ""
        self.ng1port = ""
        self.ng1username = ""
        self.ng1password = ""
        self.use_ng1_token = False
        self.ng1token = ""
        self.ng1key_file = "ng1key.key"
        self.ng1key = ""
        self.expiry_time = -1

def create_cred(creds, cred_filename):
    """
    This function encrypts the password or token and then stores the key in a key file.
    It also stores the encrypted password or token into a credentials file, with all other target information.
    :creds: An instance of the Credentials class that holds all of the nG1 API connection and authentication parameters.
    :cred_filename: A string that is the name of the local credentials file. CredFile.ini is the default.
    :return: True if successful, False if unsuccessful.
    """
    try:
        os_type = sys.platform
        if os_type == 'linux':
            creds.ng1key_file = '.ng1key.key' # Prepend a dot to the filename to hide it in Linux.
        elif os_type == 'win32' or os_type == 'win64':
                creds.ng1key_file = 'ng1key.key' # Default key filename if Windows.
        else:
            pass # Could not determine OS type

        # If there exists an older key file, This will remove it.
        if os.path.exists(creds.ng1key_file):
            os.remove(creds.ng1key_file)
        if creds.ng1token == '': # The user entered a password.
            # The user entered a password, so we will store the key needed to decrypt that password.
            # Open the ng1key.key file and place the key in it.
            creds.ng1key = Fernet.generate_key()
            fng1 = Fernet(creds.ng1key)
            creds.ng1password = fng1.encrypt(creds.ng1password.encode()).decode()
            del fng1
            with open(creds.ng1key_file, 'w') as key_in:
                key_in.write(creds.ng1key.decode())
                # Hiding the key file. The below code learns OS and tries to hide key file accordingly.
                if os_type == 'win32' or os_type == 'win64':
                    ctypes.windll.kernel32.SetFileAttributesW(creds.ng1key_file, 2)
                else:
                    pass
        else: # The user entered a token.
            # The user entered a token, so we will store the key needed to decrypt that token.
            # Open the ng1key.key file and place the key in it.
            creds.ng1key = Fernet.generate_key()
            fng1 = Fernet(creds.ng1key)
            creds.ng1token = fng1.encrypt(creds.ng1token.encode()).decode()
            del fng1
            with open(creds.ng1key_file, 'w') as key_in:
                key_in.write(creds.ng1key.decode())
                # Hiding the key file. The below code learns OS and tries to hide key file accordingly.
                if os_type == 'win32' or os_type == 'win64':
                    ctypes.windll.kernel32.SetFileAttributesW(creds.ng1key_file, 2)
                else:
                    pass
        with open(cred_filename, 'w') as file_in: # Write the nG1 connection and user authentication parameters to the CredFile.ini file.
            file_in.write(f"# nGeniusONE Credentials file:\nng1hostname={creds.ng1hostname}\nng1username={creds.ng1username}\nng1password={creds.ng1password}\nng1token={creds.ng1token}\nng1port={creds.ng1port}\nexpirytime={creds.expiry_time}")
    except IOError as e:
        print('[ERROR] Unable to write file')
        print(f'I/O error({e.errno}): {e.strerror}')
        return False
    except PermissionError as e:
        os.remove(creds.key_file)
        print('[ERROR] Unable to write to file')
        print(f'Permissions error({e.errno}): {e.strerror})')
        return False
    except Exception as e: #handle other exceptions such as attribute errors
        print('[ERROR] Unable to write to file')
        print(f'Unexpected error({e.errno}): {e.strerror})')
        return False

    return True

def yes_or_no(question):
    reply = ""
    while reply != 'y' or reply != 'n':
        reply = str(input(question + ' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            return False
        else:
            print('The answer is invalid, please enter y or n')
            continue

def user_entry_menu(creds):
    """
    This function prompts the user to input the nG1 connection and user credentials parameters.
    The params that are entered become parameters of the creds instance.
    :creds: An instance of the Credentials class to place all the entered parameters into.
    :return: True if successful, False if unsuccessful.
    """
    try:
        # Accepting nG1 connection criteria and user credentials via user menu manual input.
        print("\nInput the required nGeniusONE connection info or type 'exit' at any time to bail out")
        ng1hostname = input("Enter the nG1 Hostname or IP Address: ")
        if ng1hostname.lower() == 'exit':
            return False
        else:
            creds.ng1hostname = ng1hostname
        ng1port = input("Enter nG1 connection port or <enter> for default '443': ")
        if ng1port == '': # Use the default setting.
            creds.ng1port = 443
        elif ng1port.lower() == 'exit':
            return False
        else:
            creds.ng1port = int(ng1port)
        ng1username = input("Enter nG1 Username or <enter> for default 'administrator': ")
        if ng1username == '': # Use the default setting.
            creds.ng1username = 'administrator'
        elif ng1username.lower() == 'exit':
            return False
        else:
            creds.ng1username = ng1username
        # Give the user the option to use an API Token or a username:password pair.
        if yes_or_no("Use Token instead of Password?") == True:
            ng1token = input("Enter nG1 User Token: ")
            if ng1token.lower() == 'exit':
                return False
            else: # They said yes, set the creds parameter.
                creds.ng1token = ng1token
                creds.ng1password = ''
                creds.use_ng1_token = True
        else: # They said no, so we will ask them to enter a password.
            while True:
                # Do not echo the user entered password characters to the terminal.
                ng1password = stdiomask.getpass(prompt="Enter nG1 Password: ")
                confirm = stdiomask.getpass("Confirm nG1 Password: ") # They need to type it in again.
                if ng1password == confirm: # The two password entries match.
                    creds.ng1password = ng1password
                    creds.ng1token = ''
                    creds.use_ng1_token = False
                    break
                elif ng1password.lower() == 'exit':
                    return False
                else: # The two password entries do not match, ask them to try again.
                    print("Passwords do not match")
                    print('Try again')
                    continue

        expiry_time = input("Enter the expiry time for key file in minutes or <enter> for default 'never expire': ")
        if expiry_time == '': # Use the default setting.
            creds.expiry_time = -1
        elif expiry_time.lower() == 'exit':
            return False
        else:
            creds.expiry_time = int(expiry_time)
    except Exception as e: # Handle any and all exceptions.
        print('[ERROR] The entry menu has failed')
        print(f'Unexpected error({e.errno}): {e.strerror})')
        return False

    return True

def main():

    # Create an instance of the Credentials class to store all the ng1 API credentials and authentication parameters.
    creds = Credentials()
    # So that other scripts can use this connection info without any menu, we must hardcode the cred_filename.
    cred_filename = 'CredFile.ini'

    # Prompt the user to input the nG1 connection and user authentication parameters.
    if user_entry_menu(creds) == False: #The credentials params entry menu has failed:
        print('Main: The user_entry_menu has failed')
        print('\nExiting the script...')
        sys.exit()

    # Create the credentials file.
    if create_cred(creds, cred_filename) == False: # The create credentials file function has failed.
        print('Main: create_cred has failed')
        print('\nExiting the script...')
        sys.exit()
    else: # The credentials file was created successfully.
        print(f"\nThe credentials file {cred_filename} was created at {time.ctime()}")
        print('\nProgram execution has completed successfully')

if __name__ == "__main__":
    main()
