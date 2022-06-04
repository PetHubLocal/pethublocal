"""
 Pet Hub Local Constants
"""
from logging import DEBUG
# from logging import INFO

# Time for config checker to sleep
SLEEPTIME = 5

# Enrich response with Tag for Pet Door
TAGLOOKUP = True
LOGLEVEL = DEBUG
VERSION = 2
REINITDAYS = 1  # Number of days before re-initialising Home Assistant entities

# Default Values added to config
BOOTLOADER = '1.177'           # Bootloader version used during firmware update
FIRMWAREVERSION = '2.43'       # Firmware Version
TIMEZONE = 'Local'             # Report time in UTC as it is sent, or Local for localtime
FIRMWARECACHE = True           # Cache a local copy of your firmware
FIRMWAREFORCEDOWNLOAD = False  # Force Download cached copy even if firmware has been locally cached
EXTERNALDNSSERVER = '8.8.8.8'  # Default DNS Server, using Google
LOGNAME = "pethublocal.log"    # Log Name

# Pet Hub Config file
CONFIGFILE = 'pethubconfig.json'
PHC = 'pethubconfig'

LONG_SERIAL_ORDER = [10, 7, 8, 11, 0, 5, 12, 13, 15, 1, 2, 14, 4, 6, 3, 9]  # Order of Long Serial from Long Serial Key
FIRMWARE_STATIC_XOR_KEY = bytes.fromhex('a71e569f3ed42a73cc4170bbf3d34e69')  # Firmware Static XOR key

# SureHub Endpoints - Frontend API endpoint for retrieving start.json
SUREHUBAPP = 'app.api.surehub.io'  # Browser API Endpoint
SUREHUBHOST = 'hub.api.surehub.io'  # Hub Endpoint

# User Agents
# Hub User Agent when downloading credentials or firmware from SureHub as the hub
HUBUSERAGENT = 'curl/7.22.0 (x86_64-pc-linux-gnu) libcurl/7.22.0 OpenSSL/1.0.1 zlib/1.2.3.4 libidn/1.23 librtmp/2.3'
# App User Agent when calling API Endpoint to retrieve the cloud config
APPUSERAGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36'

# Register defaults,
# Hub has 45 Bytes for state, then 10 devices with 8 bytes for mac address and 8 bytes for connected device state
REGISTERSHUB = (('0' * 90) + (('0' * 16) + 'fc' + ('f' * 14)) * 10)
# Pet door has 650 registers and check the code for what they all mean.
REGISTERSPETDOOR = '00' * 605


# MQTT Topics - Home Assistant MQTT Discovery and PetHubLocal

# Pet Hub Local Topic
PH_T = 'pethub/'
PH_HUB_T = f'{PH_T}hub/'  # Topic the hub uses
PH_HA_T = f'{PH_T}ha/'  # Home Assistant State topic for JSON blobs

# Home Assistant Configuration Topics
HA_T = 'homeassistant/'
HA_SENSOR = f'{HA_T}sensor/{PH_T}'  # Device Sensor Topic
HA_SWITCH = f'{HA_T}switch/{PH_T}'  # Device Switch Topic for devices being added with on/off switch

CFG = 'Config'
DEV = 'Devices'
PET = 'Pets'

NAME = 'Name'
SN = 'Serial_Number'
MAC = 'Mac_Address'
PID = 'Product_Id'
CFEW = 'Curfew_Enabled'
CFEWS = 'Curfews'
LMODE = 'Locking_Mode'
