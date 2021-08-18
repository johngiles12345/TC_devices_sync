================
TC_devices_sync
================

A python program for Transcanada that integrates MIB II device attributes found
in their Solarwinds CSV export to the nGeniusONE device configuration to produce
very specific Network Service names that contains the desired fields from both.
Then that network service is placed into the dashboard hierarchy based on location
names used to produce the Network Service name (label). The new network service is
added to the correct domain in the hierarchy.

-------------------------
Preparing for Development
-------------------------

#. Ensure ''pip'' and ''pipenv'' are installed.
#. Clone repository: ''git clone git@github.com:jgiles/TC_devices_sync''.
#. ''cd'' into repository.
#. Fetch development dependencies ''make install''.
#. Activate virtualenv: ''pipenv shell''.

Usage
-------------------------
Prerequisite:
You must run a one time script called cred_script_nG1.py first. This is a menu driven
script that will prompt the user for connection and credentials to establish a connection
to the nGeniusONE API. A file is produced from this script called CredFile.ini.
This CredFile.ini is read by this script so it knows how to connect to the nG1 API.
In this way, this script can be run programmatically without any human interaction.

There are no mandatory arguments. The optional --set flag will control if any post
operations are performed.

Example without --set flag:

::

    $ TC_devices_sync

#. Reads CredFile.ini and connects to the nG1 API.
#. Reads in the list of providers from a local file 'provider_list.txt'.
#. If provider_list.txt is not found, a default hardcoded list is used.
#. Does a get to nG1 API for all the devices that are Active MIBII devices.
#. Gets the interfaces for each Active MIBII device.
#. Determines by name which interface is the WAN interface and which provider.
#. Looks for a local file 'solarwinds_config_current.csv' and reads it in.
#. Looks for the intersection of Active MIBII devices in nG1 to those listed in the solarwinds csv file.
#. For those devices that are common, other attributes are read from solarwinds csv file (ScadaType, LOB, MLOB).
#. This data including solarwinds attributes is written to a local file 'devices_intersection.csv'.
#. Gets all the current network services in nG1 config that are MIBII related (names ending with '_MIB Polling').
#. Gets the current alert profiles in nG1 config and their ID numbers.
#. Based on the speed of the WAN interfaces in nG1 config, the alert profile ID number with a matching speed is associated to the WAN interface.
#. Using the attributes for each WAN interface, the network service name is assembled based on the customer's desired format
#. The network service names are filtered by the list of already existing network services
#. The resulting filtered list of network services to be added is written to a local file 'net_srv_add_candidates.csv'.
#. Valid network services are determined by comparing the list of nG1 (Active Devices) MIBII WAN interfaces (Active or not) to those listed in the intersection data with solarwinds csv. Meaning that there should be a network service in the nG1 config that has this interface as a member.
#. The valid network service list is compared to the list of existing network services to find any stale, orphaned services.
#. The list of network services that are orphaned (should be deleted) is output to a local file 'net_srv_delete_candidates.csv'.

Example with --set flag:

::

    $ TC_devices_sync --set

In addition to the above steps, these steps are executed when the --set flag is specified.

#. The list of valid network services to add that are not already in the nG1 config are created.
#. Get the current list of domains existing in the nG1 config.
#. Verify that there is a WAN domain and get its ID number, if not, create the WAN domain  and get the ID.
#. For each new network service added, determine the organization level domain name based on MLBO and the corpscada_type.
#. If the organization level Domain does not already exist, create it using the WAN domain as the parent.
#. For each new network service added, determine the region level domain name based on LOB.
#. If the region level Domain does not already exist, create it using the organization domain from the previous step as the parent.
#. The region domain will have the network service as a member.

Running Tests
-------------------------

Run tests locally using ''make'' if virtualenv is active:

::


    $ make

If virtualenv isn’t active then use:

::

    $ pipenv run make
