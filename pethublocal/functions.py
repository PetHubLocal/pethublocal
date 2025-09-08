"""
 Pet Hub Shared functions
 Copyright (c) 2022, Peter Lambrechtsen (peter@crypt.nz)
"""
import ast
from datetime import datetime, timedelta
import json
import os
import re
import uuid
import base64
import jwt
import requests
from box import Box
import dns.resolver
import sys
import codecs
import urllib3

from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

from .generate import generatemessage
from .message import parse_hub
from .consts import *
from . import log
from .enums import *
from importlib.resources import files

# Disable annoying urllib HTTPS Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LastMessageFromHub = datetime.utcnow()

def external_dns_query(host, internal=False):
    """
     Query DNS entries outside default DNS server to retrieve IP address. This is so the
     public IP hub.api.surehub.io which is used by the hub can be queried from Google DNS
     rather than using the internal DNS server, as the host should have been poisoned so
     the local hub points to this service, but we need to query the real one.
    """
    resolver = dns.resolver.Resolver(configure=internal)
    if not internal:
        resolver.nameservers = [EXTERNALDNSSERVER]
    answer = resolver.resolve(host, 'A')
    retval = '127.0.0.1'
    if answer:
        retval = str(answer[0])
    return retval


def valid_serial(serial):
    """ Regex check the serial number is valid """
    return re.match('H0[01][0-9]-0[0-9]{6}', serial)


def valid_hub_mac(mac_address):
    """ Regex check the 802.15.4 MiWi Mac Address is valid """
    return re.match('^0000[0-9A-F]{12}$', mac_address)

def pascal_to_spaced(text):
    """
    Convert PascalCase string to spaced string.
    Example: 'KeepIn' -> 'Keep In'
    """
    return re.sub(r'(?<!^)([A-Z])', r' \1', text)

def download_firmware_record(surehubioip, serialnumber, bootloader, page):
    """
     Download specific record, called by download_firmware
     Using publicly queried dns IP from Google DNS then make an HTTPS POST request directly to that
     endpoint which is exactly what the hub does. This is because hub.api.surehub.io should be
     spoofed internally, but we need to query publicly. The firmware is split into 4kb pages and
     XOR encrypted with the long_serial.
    """
    page = str(page)
    url = 'http://' + surehubioip + '/api/firmware'
    headers = {
        'User-Agent': HUBUSERAGENT,
        'Content-Type': 'application/x-www-form-urlencoded', 'Host': SUREHUBHOST,
        'Connection': None, 'Accept-Encoding': None}
    postdata = 'serial_number=' + serialnumber + '&page=' + page + '&bootloader_version=' + bootloader
    response = requests.post(url, data=postdata, headers=headers, verify=False)
    response.raise_for_status()  # Ensure we notice bad responses
    payload = response.content
    filename = serialnumber + '-' + bootloader + '-' + str(page).zfill(2) + '.bin'
    with open(filename, "wb") as fp:
        fp.write(payload)
        fp.close()


def download_firmware(serialnumber, forcedownload):
    """
     Download firmware for hub from SurePetCare, loop through pages based on header.
    """
    surehubio = external_dns_query(SUREHUBHOST)  # External query for hub.api.surehub.io
    return_message = ""
    if surehubio:
        log.info('SureHub Host %s IP Address: %s', SUREHUBHOST, surehubio)
        if valid_serial(serialnumber):
            firmware = serialnumber + '-' + BOOTLOADER + '-00.bin'
            if not os.path.isfile(firmware) or forcedownload:
                # Download first firmware file and inspect the header for the number of records to download
                log.info('Downloading first firmware record to get header information')
                download_firmware_record(surehubio, serialnumber, BOOTLOADER, 0)
                with open(firmware, "rb") as f:
                    # Read the 36 bytes of file header
                    byte = f.read(36).decode("utf-8").split()
                    # PFX Record count in hex adding 6
                    recordcount = int(byte[2], 16) + 6
                    log.info('Count: %s', str(recordcount))
                    for counter in range(1, recordcount):
                        log.info("Download remaining record: %s", str(counter))
                        download_firmware_record(surehubio, serialnumber, BOOTLOADER, counter)
                return_message = "Firmware successfully downloaded"
            else:
                return_message = 'Firmware already downloaded ' + firmware
        else:
            return_message = 'Invalid Serial Number passed, make sure it is H0xx-xxxxxxx'
    else:
        return_message = 'Issue with External DNS lookup'
    return return_message


def download_credentials(hub, serial_number, mac_address, firmware_version):
    """
     Credentials file request hub makes each time it boots to retrieve the MQTT endpoint and client certificate
     serial_number=H0xx-0xxxxxx&mac_address=0000xxxxxxxxxxxx&product_id=1&firmware_version=2.43
    """
    surehubio = external_dns_query(SUREHUBHOST)  # External query for hub.api.surehub.io
    if surehubio:
        log.info('SureHub Host %s IP Address: %s', SUREHUBHOST, surehubio)
        if valid_serial(serial_number) and valid_hub_mac(mac_address):
            creds_filename = serial_number + '-' + mac_address + '-' + firmware_version + '.bin'
            url = 'https://' + surehubio + '/api/credentials'
            headers = {'User-Agent': HUBUSERAGENT,
                       'Content-Type': 'application/x-www-form-urlencoded', 'Host': SUREHUBHOST,
                       'Connection': None, 'Accept-Encoding': '*/*'}
            postdata = 'serial_number=' + serial_number.upper() + '&mac_address=' \
                       + mac_address.upper() + '&product_id=1&firmware_version=' + str(firmware_version)
            log.info('Credentials Post Header: ' + postdata)
            try:
                response = requests.post(url, data=postdata, headers=headers, verify=False)
                response.raise_for_status()  # ensure we notice bad responses
                payload = response.content
                # Creating original file from https response
                with open(creds_filename, "wb") as fp:
                    fp.write(payload)
                    fp.close()
                # Update hub device with client_cert retrieved from credentials response
                uuid_value = str(payload).split(':')[2]
                client_cert = str(payload).split(':')[8].replace("'", '').replace("\n", '')
                log.info("Downloaded Client Certificate -%s-", client_cert)
                hub.merge_update({
                    'UUID': uuid_value,
                    'Client_Cert': client_cert})
                return 'Download Credentials Successful'
            except:
                return 'Credentials file download failed'
        else:
            return 'Invalid Serial Number or MAC Address passed, make sure it is H0xx-xxxxxxx ' \
                   'and 0000xxxxxxxxxxxx with 4 0s prefixing the hardware mac'
    else:
        return 'Issue with External DNS lookup'


def token_expiry(token):
    """ Check if JWT auth token has expired """
    tokenjwt = jwt.decode(token, options={"verify_signature": False})
    log.info('Check Token Expiry JWT %s', str(tokenjwt))
    tokenexp = datetime.utcfromtimestamp(tokenjwt['exp'])
    log.info('JWT Token Expiry %s', str(tokenexp))
    return True if tokenexp - datetime.utcnow() < timedelta(days=1) else False


def download_start(pethubconfig):
    """ Download the start jsom payload from Surepet using requests """
    phc_config = pethubconfig[CFG].Cloud
    if 'Token' in phc_config:  # Check JWT hasn't expired
        if token_expiry(phc_config['Token']):
            phc_config.LoggedIn = False
            del phc_config['Token']

    # Authenticate to Login Endpoint
    while 'Token' not in phc_config or phc_config.LoggedIn is False:
        if 'Username' not in phc_config:
            initial = input('Cloud Config - Start initial setup Y/N?')
            if len(initial) > 0 and initial[0].upper() == 'Y':
                username = input('SurePetCare Cloud EMail Address: ')
                password = input('SurePetCare Cloud Password: ')
                phc_config.merge_update({'Username': username, 'Password': password})
            else:
                log.info("Cloud Config: Rejected initial setup, exiting")
                sys.exit(1)
        log.info('Cloud Config: Logging into Surepet to get JWT Bearer Token')
        url = f'https://{SUREHUBAPP}/api/auth/login'
        headers = {'User-Agent': APPUSERAGENT,
                   'Content-Type': 'application/json', 'Accept': '*/*'}
        if 'device_id' not in phc_config:  # Generate Device ID random UUID if it is missing
            phc_config['device_id'] = str(uuid.uuid4())
        postdata = json.dumps({
            'email_address': phc_config.Username,
            'password': phc_config.Password,
            'device_id': phc_config['device_id']
        })
        log.info('Cloud Config: Authenticate to retrieve JWT Bearer Token: %s', postdata)
        try:
            response = requests.post(url, data=postdata, headers=headers, verify=False)
            response.raise_for_status()  # Ensure we notice bad responses
            log.info('Authentication successful response.json() %s', json.dumps(response.json()))
            token = response.json()['data']['token']
            if token_expiry(token):
                Exception('Expired Token')
                phc_config.LoggedIn = False
                del phc_config['Token']
                pethubconfig[CFG].Cloud = phc_config
                config_save(pethubconfig)
                sys.exit(1)
            else:
                phc_config.merge_update({'Token': token})
                phc_config.LoggedIn = True
                log.info('Cloud Config: Updating Configuration with Valid JWT: %s', token)
                # log.info('Updating Configuration with Valid JWT: %s', str(config_update(update=new_token)))
        except requests.exceptions.HTTPError as err:
            phc_config.LoggedIn = False
            if 'Token' in phc_config:
                del phc_config['Token']
            pethubconfig[CFG].Cloud = phc_config
            config_save(pethubconfig)
            print(err, type(err))
            sys.exit(1)

    # Download start information
    resp = {}
    if 'Token' in phc_config:
        log.info('Cloud Config: Using JWT Bearer Token to download configuration')
        url = f'https://{SUREHUBAPP}/api/me/start'
        headers = {'User-Agent': APPUSERAGENT,
                   'Authorization': 'Bearer ' + phc_config['Token'],
                   'Accept': 'application/json'}
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()  # Ensure we notice bad responses
            log.info(response.json()['data'])
            startjson = "start-" + str(datetime.now().strftime("%Y%m%d-%H%M%S")) + ".json"
            with open(startjson, 'w') as fp:
                json.dump(response.json(), fp, indent=4)
            phc_config.merge_update({'StartJSON': startjson})
            log.info('Cloud Config: Download successful response: %s', response)
            resp = response.json()['data']
        except requests.exceptions.HTTPError as err:
            phc_config.LoggedIn = False
            del phc_config['Token']
            pethubconfig[CFG].Cloud = phc_config
            config_save(pethubconfig)
            log.info('Cloud Config: Download Start Failed:', str(err))
            sys.exit(1)
    pethubconfig[CFG].Cloud = phc_config
    config_save(pethubconfig)
    return Box(resp)


def config_defaults():
    """ Default config """
    return Box({CFG: {"Deployment": "Setup",
                      "Timezone": TIMEZONE,
                      "Last_HA_Init": 10,
                      "Get_State": True,
                      "Last_Updated": "2022-05-16 06:36:10",
                      "Cloud": {
                          "LoggedIn": False
                      },
                      "Web": {"Host": "0.0.0.0",
                              "HTTPPort": 80,
                              "HTTPSPort": 443,
                              "Cert": "hub.pem",
                              "CertKey": "hub.key"},
                      "MQTT": {"Host": "127.0.0.1"},
                      "Firmware": {"Cache": FIRMWARECACHE,
                                   "Force_Download": FIRMWAREFORCEDOWNLOAD}
                      },
                DEV: {},
                PET: {}
                })


def config_update(**kwargs):
    """ Update PetHubConfig using either object passed or load the file"""
    if 'config' in kwargs:
        pet_hub_config = Box(kwargs['config'])
    else:
        pet_hub_config = Box(config_load())
    if 'update' in kwargs:
        pet_hub_config.merge_update(kwargs['update'])
    pet_hub_config_copy = pet_hub_config.copy()
    return config_save(pet_hub_config_copy)


def config_local(**kwargs):
    """ Build or update pethubconfig.json from local config """
    config = Box()
    # Check status of the config file and build if missing.
    if 'config' in kwargs:
        log.info('Config Cloud - Config Passed')
        config = Box(kwargs['config'])
    elif os.path.isfile(CONFIGFILE):
        log.info('Config Cloud - Local %s exists', CONFIGFILE)
        with open(CONFIGFILE) as json_file:
            config = Box(json.load(json_file))
    elif 'serialnumber' in kwargs:
        log.info('Config Cloud - Config missing but using username and password passed')
        config.merge_update({CFG: {'Deployment': 'Local'}})
        # Well done you have the hub certificate password, so create a local config.
        if 'password' in kwargs:
            config.merge_update({
                DEV: {
                    kwargs['serialnumber'].upper(): {
                        'Hub': {
                            'cert_password': kwargs['password'].upper()
                        }
                    }
                }
            })
    else:
        log.info('No valid parameters passed, exiting')
        sys.exit(1)
    log.info('Config Updated: %s', str(config_save(config)))


def config_load(setup=False, force=False):
    """ Load config into python box dict """
    config = Box()
    if os.path.isfile(CONFIGFILE):
        log.info('Loading Config file %s', CONFIGFILE)
        config = Box.from_json(filename=CONFIGFILE)
    else:  # Missing config so building it
        log.info('Missing Config file building from defaults')
        config.merge_update(config_defaults())
        config_save(config)

    if setup:
        if config.Config.Deployment != 'Setup':
            log.info('Current Deployment %s', config.Config.Deployment)

        cloud_local = input('Use exist SurePetCare Cloud (C) or build empty Local config (L) C/L ? ')
        if len(cloud_local) > 0 and re.match(r'^C|^L', cloud_local.upper()):
            if cloud_local[0].upper() == 'C':
                config.merge_update({'Config': {'Deployment': 'Cloud'}})
                config_save(config)
                log.info('Building from Cloud Configuration, starting DNS check')
                log.info('This is *VITAL* as you need to update your internal DNS to point %s to this host '
                         'running PetHubLocal so that the hub connects to this host not the internet', SUREHUBHOST)
                while True:
                    log.info('External DNS entry for %s: %s', SUREHUBHOST, external_dns_query(SUREHUBHOST))
                    log.info('Internal DNS entry for %s: %s', SUREHUBHOST, external_dns_query(SUREHUBHOST, True))
                    dns_check = input(f'Is the Internal DNS updated to point to this host Y/N? \n')
                    if len(dns_check) > 0 and dns_check[0].upper() == 'Y':
                        break
                start = Box({})
                if 'StartJSON' in config.Config.Cloud:
                    print('')
                    dl_start = input(f'Start File {config.Config.Cloud.StartJSON} download new start Y/N? ')
                    if len(dl_start) > 0 and dl_start[0].upper() == 'Y':
                        del config.Config.Cloud['StartJSON']
                    else:
                        log.info('Using existing file')
                        start = Box.from_json(filename=config.Config.Cloud.StartJSON)
                if 'StartJSON' not in config.Config.Cloud:
                    start.merge_update(download_start(config))
                if len(start.data) > 5:
                    log.info('Start downloaded, saving base config %s', start.to_json())
                    continue_setup = input('Continue with setup using this start file? If you need to make changes to it before applying to the config, now is the time to do so. Press Y to continue or N to make changes')
                    if len(continue_setup) > 0 and continue_setup[0].upper() == 'N':
                        log.info('Exiting setup, please edit the start file %s and re-run', config.Config.Cloud.StartJSON)
                        sys.exit(0)
                    config.merge_update(start_to_pethubconfig(config, start))
                    config_save(config)
                    log.info('Start parsed and saved to config')
                    dl_cloud = input('Download Credentials and Firmware for Hub (highly recommended)? Y/N ')
                    if len(dl_cloud) > 0 and dl_cloud[0].upper() == 'Y':
                        for hubs, devs in config.Devices.items():
                            for dev, key in devs.items():
                                if dev == 'Hub':
                                    log.info('Current Hub Firmware %s', key.Device.Firmware)
                                    serial_number = key.Serial_Number
                                    mac_address = key.Mac_Address
                                    firmware = str(key.Device.Firmware)
                                    log.info('Downloading Current Firmware for %s', serial_number)
                                    log.info(download_firmware(serial_number, force))
                                    # Find the XOR Key and Long Serial aka Certificate Password based off firmware
                                    xor_key, long_serial = find_firmware_xor_key(serial_number, BOOTLOADER)
                                    log.info('XOR Key: %s Long Serial: %s', xor_key, long_serial)
                                    config.merge_update({'Devices': {hubs:{dev:{
                                        'XOR_Key': xor_key,
                                        'Long_Serial': long_serial
                                    }}}})
                                    try:
                                        before_decimal = int(firmware.split('.')[0])
                                        after_decimal = int(firmware.split('.')[1])
                                        if (before_decimal == 2 and after_decimal > 201) or before_decimal > 2:
                                            log.error("I'm sorry to say that you are running version %s. "
                                                      "firmware after version 2.201 does not work with this project thanks to SurePet.\n"
                                                      "Whatsmore, there is currently no way to downgrade the firmware from this level.", firmware)
                                            sys.exit(1)
                                        if before_decimal == 2 and after_decimal > 43:
                                            log.info("Your device has been upgraded to version %s. Since it isn't running 2.43 "
                                                     "the Hub now checks the server certificate is legitimate before connecting (boo! :( ) \n"
                                                     "Fortunately, your firmware DOES support downgrading to 2.43 which for the moment is easy as holding "
                                                     "the reset button underneath the hub when the DNS is poisoned to point to PetHubLocal (Yay!)", firmware)
                                            # Build specific 2.43 firmware that doesn't check the SSL Cert for this hub using XOR key
                                            build_firmware(xor_key, serial_number)
                                    except (IndexError, ValueError):
                                        log.info(f"Could not parse firmware version: {firmware}")
                                        sys.exit(1)

                                    log.info('Downloading Credentials for %s MAC: %s Firmware: %s', serial_number, mac_address, firmware)
                                    log.info(download_credentials(key, serial_number, mac_address, firmware))

                    mqtt_broker = input('MQTT Broker running on this host? Y/N ')
                    if len(mqtt_broker) > 0 and mqtt_broker[0].upper() == 'N':
                        mqtt_broker_ip = input('MQTT Broker IP:')
                        if len(mqtt_broker_ip) > 0:
                            config.merge_update({'Config':{'MQTT':{'Host': mqtt_broker_ip}}})
                            log.info('Broker IP Updated to: %s', mqtt_broker_ip)
                        mqtt_custom_credentials = input('Does your MQTT Broker need a username and password to connect on 1883? Y/N ')
                        if len(mqtt_custom_credentials) > 0 and mqtt_custom_credentials[0].upper() == 'Y':
                            mqtt_client_username = input('MQTT Client Username:')
                            mqtt_client_password = input('MQTT Client Password:')
                            if len(mqtt_broker_ip) > 0:
                                config.merge_update({'Config':{'MQTT':{'ClientUsername': mqtt_client_username}}})
                                config.merge_update({'Config':{'MQTT':{'ClientPassword': mqtt_client_password}}})
                                log.info('Broker Username and password updated to: %s and %s', mqtt_client_username, mqtt_client_password)
                    else:
                        config.merge_update({'Config': {'MQTT': {'Host': '127.0.0.1'}}})
                    config_save(config)
                else:
                    log.info('Start failed to download, perhaps your password is wrong?')
            if cloud_local[0].upper() == 'L':
                log.info('Building from Local Configuration')
                config.merge_update({CFG: {'Deployment': 'Local'}})
    return config


def config_addon(username, password):
    """ Create Config if it doesn't exist when using the Home Assistant Addon """
    state = False
    if os.path.isfile(CONFIGFILE):
        log.info(f'Config file {CONFIGFILE} found, ready to start')
        state = True
    elif not os.path.isfile(CONFIGFILE) and len(username) > 4 and len(password) > 2:
        config = Box()
        config.merge_update(config_defaults())
        config.merge_update({'Config': {'Deployment': 'Addon',
                                        'Cloud': {
                                            'Username': username,
                                            'Password': password}}})
        config_save(config)
        # log.info('External DNS entry for %s: %s', SUREHUBHOST, external_dns_query(SUREHUBHOST))
        # log.info('Internal DNS entry for %s: %s', SUREHUBHOST, external_dns_query(SUREHUBHOST, True))

        start = Box()
        if 'StartJSON' not in config.Config.Cloud:
            start.merge_update(download_start(config))

        if len(start) > 5:
            config.merge_update(start_to_pethubconfig(config, start))
            config_save(config)
            log.info('Start parsed and saved to config')

            for hubs, devs in config.Devices.items():
                for dev, key in devs.items():
                    if dev == 'Hub':
                        log.info('Current Hub Firmware %s', key.Device.Firmware)
                        serial_number = key.Serial_Number
                        mac_address = key.Mac_Address
                        firmware = str(key.Device.Firmware)
                        log.info('Downloading Current Firmware for %s', serial_number)
                        log.info(download_firmware(serial_number, False))
                        # Find the XOR Key and Long Serial aka Certificate Password based off firmware
                        xor_key, long_serial = find_firmware_xor_key(serial_number, BOOTLOADER)
                        config.merge_update({'Devices': {hubs:{dev:{
                            'XOR_Key': xor_key,
                            'Long_Serial': long_serial
                        }}}})
                        try:
                            before_decimal = int(firmware.split('.')[0])
                            after_decimal = int(firmware.split('.')[1])
                            if (before_decimal == 2 and after_decimal > 201) or before_decimal > 2:
                                log.error("I'm sorry to say that you are running version %s. "
                                          "firmware after version 2.201 does not work with this project thanks to SurePet.\n"
                                          "Whatsmore, there is currently no way to downgrade the firmware from this level.", firmware)
                                sys.exit(1)
                            if before_decimal == 2 and after_decimal > 43:
                                log.info("Your device has been upgraded to version %s. Since it isn't running 2.43 "
                                         "the Hub now checks the server certificate is legitimate before connecting (boo! :( )\n"
                                         "Fortunately, your firmware DOES support downgrading to 2.43 which for the moment is easy as holding "
                                         "the reset button underneath the hub when the DNS is poisoned to point to PetHubLocal (Yay!)", firmware)
                                # Build specific 2.43 firmware that doesn't check the SSL Cert for this hub using XOR key
                                build_firmware(xor_key, serial_number)
                        except (IndexError, ValueError):
                            log.info(f"Could not parse firmware version: {firmware}")
                            sys.exit(1)
                        log.info('Downloading Credentials for %s MAC: %s Firmware: %s', serial_number, mac_address, firmware)
                        log.info(download_credentials(key, serial_number, mac_address, firmware))

            config.merge_update({'Config': {'MQTT': {'Host': '127.0.0.1'}}})
            config_save(config)
            state = True
    else:
        log.info(f'Missing {CONFIGFILE} or username and password')
    return state


def config_save(pethubconfig):
    """ Save Config """
    status = pethubconfig[CFG]
    status['Last_Updated'] = timestamp_now()
    pethubconfig[CFG] = status
    pethubconfigcopy = pethubconfig.copy()
    try:
        with open(CONFIGFILE, 'w') as fp:
            json.dump(pethubconfigcopy, fp, indent=4)
        return True
    except ValueError:
        return False


def json_print(jsondata):
    """ Pretty print JSON """
    jsonresult = json.dumps(jsondata, indent=4)
    print("Result:\n" + highlight(jsonresult, JsonLexer(), TerminalFormatter()))


def json_print_nohighlight(jsondata):
    """ Pretty print JSON without highlighting so it logs nicely """
    return "Result:\n" + json.dumps(jsondata, indent=4)


def timestamp_now():
    """ Create local time timestamp as a string """
    return str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def update_pethubconfig_status(pethubconfig):
    """ Update Status """
    status = pethubconfig[CFG]
    status['Last_Updated'] = timestamp_now()
    pethubconfig[CFG] = status


def start_to_pethubconfig(config, data):
    """
     Convert surepetcare cloud start.json to pethubconfig configuration json file.
     The Hub and Pet Door use registers to control their state so storing it in the database seemed
     the best way to it as hub registers is 205 Bytes, Pet door registers is 650
    """
    # Remove data element at top level element if it exists
    if 'data' in data:
        data = data.data

    # Tags box
    tags = data.tags

    if data.devices is None or len(data.devices) == 0:
        log.error("No devices found in payload from SurePetCare. Make sure you have a hub and accessory registered to your account. \n"
                  "You may not wish to connect your V1 hub to the internet for this, it may result in a firmware upgrade that breaks this project. \n"
                  "My only suggestion is to use a V2 hub and temporarily pair it with your accessories. That will generate the correct config in the cloud. \n"
                  "After that, come back here and start the cloud set up again. Select to download a new start file. When given the option, exit the set up. "
                  "Then, manually update the start.json file to replace the references to the V2 hub with the V1 hub. Essentially pretending this was what was pulled from the cloud. \n"
                  "Then, come back once more and run the PetHubLocal setup. This time, say to NOT download a new start file and the installer will use the one you just updated. \n"
                  "In particular, the serial number and MAC address of the V1 hub will need updating in the start file. There may be other differences, go through it line by line.")
        sys.exit(1)

    # Parent Serial Number, assumption this is always the first device serial number.
    parent_serial = data.devices[0].serial_number
    for device in data.devices:
        if 'name' in device:
            name = device.name
        elif 'serial_number' in device:
            name = device.serial_number
        else:
            name = device.mac_address
        device_result = Box({'Name': name})
        # log.debug(f"Adding Device: {name}")

        fields = ['mac_address', 'serial_number', 'product_id', 'index', 'updated_at']
        for key, val in device.items():
            if key in fields:
                device_result.merge_update({key.title(): val})

        if device.product_id in [1]:  # Add Hub Index
            device_result.merge_update({'Index': 'Hub'})

        if device.product_id in [4, 6, 8]:  # Add Counter
            device_result.merge_update({'Send_Counter': 0, 'Receive_Counter': 0})

        if device.product_id in [3, 4, 6, 8]:  # Add Default values
            device_result.merge_update({'Last_Device_Update': 100})

        if 'control' in device:
            control_fields = ['led_mode', 'pairing_mode', 'learn_mode', 'fast_polling', 'tare', 'training_mode']
            for key, val in device.control.items():
                if key in control_fields:
                    device_result.merge_update({key.title(): val})
            if 'version' in device:
                device_result.merge_update({'Main_Version': str(device.version)})

            # Pet Door or Cat Flap
            if device.product_id in [3, 6]:
                if device.product_id == 3 and 'curfew' in device.control:
                    # Pet Door Curfew, which is completely different to Cat Flap
                    if 'enabled' in device.control.curfew:
                        device_result.merge_update({'Curfew_Enabled': device.control.curfew.enabled})
                    if 'lock_time' in device.control.curfew:
                        device_result.merge_update({
                            'Curfews': device.control.curfew.lock_time + "-" + device.control.curfew.unlock_time})

                if device.product_id == 6 and 'curfew' in device.control:
                    # Cat Flap Curfew, why do you need to have 4 curfews
                    # for the Cat Flap and a single for Pet Door?? WHY???
                    if len(device.control.curfew) > 0:
                        curfews = ''
                        # Loop through all the curfews and create a single string "hh:mm-hh:mm,hh:mm-hh:mm" for
                        # each enabled curfew where the start end is - deimited and each curfew is comma separated
                        for curfew in device.control.curfew:
                            if curfew.enabled:
                                if curfew != device.control.curfew[0]:
                                    # Add a comma delimiter unless it's the last entry
                                    curfews += ','
                                curfews += curfew.lock_time + '-' + curfew.unlock_time
                        device_result.merge_update({'Curfew_Enabled': True})
                        device_result.merge_update({'Curfews': curfews})
                    else:
                        device_result.merge_update({'Curfew_Enabled': False, 'Curfews': ''})

                if 'locking' in device.control:
                    lockingmode = device.control.locking
                else:
                    if 'locking' in device.status:
                        lockingmode = device.status.locking.mode
                    else:
                        lockingmode = 0
                device_result.merge_update({LMODE: lockingmode})

            # Feeder
            if device.product_id == 4:
                device_result.merge_update({'Lid_State': 'Closed'})
                if 'bowls' in device.control:
                    if device.control.bowls.type == 4:  # Two Bowls
                        bowlcount = 2
                    elif device.control.bowls.type == 1:  # One Bowl
                        bowlcount = 1
                    else:  # I dunno
                        bowlcount = 0
                    device_result.merge_update({'Bowl_Count': bowlcount})
                    if 'settings' in device.control.bowls:
                        bowltarget = []
                        bowlweight = []
                        for setting in device.control.bowls.settings:
                            if setting.target > 0:
                                bowltarget.append(setting.target)
                                bowlweight.append(0)
                        device_result.merge_update({'Bowl_Target': bowltarget})
                        device_result.merge_update({'Bowl_Weight': bowlweight})
                        device_result.merge_update({'Bowl_Delta': bowlweight})
                if 'lid' in device.control:
                    device_result.merge_update({'Close_Delay': device.control.lid.close_delay})

            # Poseidon
            if device.product_id == 8:
                device_result.merge_update({'Bowl_Count': 1})
                device_result.merge_update({'Bowl_Weight': [0]})
                device_result.merge_update({'Bowl_Delta': [0]})

        if 'status' in device:
            if 'online' in device.status and device.status.online:
                device_result.merge_update({'State': 'Online'})
            else:
                device_result.merge_update({'State': 'Offline'})

            statusfields = ['product_id', 'learn_mode']
            for key, val in device.status.items():
                if key in statusfields:
                    device_result.merge_update({key.title(): val})
            if 'battery' in device.status:  # Battery where we can get large floating number
                device_result.merge_update({'Battery': str(round(device.status.battery, 4)), 'BatteryADC': 0})
            if 'version' in device.status:
                for key, val in device.status.version.items():
                    for subkey, subval in val.items():
                        device_result.merge_update({key.title(): {subkey.title(): str(subval)}})
            if 'signal' in device.status:
                signalfields = ['device_rssi', 'hub_rssi']
                for key, val in device.status.signal.items():
                    if key in signalfields:
                        device_result.merge_update({key.title(): val})

        # If Hub or Pet Door we need to store the registers.
        if device.product_id == 1:
            # Add Registers and uptime as we get it hourly from the hub
            device_result.merge_update({'Registers': REGISTERSHUB, 'Uptime': "0"})
        elif device.product_id == 3:
            device_result.merge_update({'Registers': REGISTERSPETDOOR})

        if 'tags' in device:  # Add provisioned device tags
            for tag in device.tags:
                tagindex = str(tag.index)
                tagid = tag.id
                # Cat flap and feeders have a profile, On cat flap profile = 3 = inside only
                if 'profile' in tag:
                    profile = tag.profile
                else:
                    profile = 0
                tag = str([x for x in tags if x["id"] == tagid][0].tag)
                device_result.merge_update({'Tags': {tagindex: {'Tag': tag, 'Profile': profile}}})

        # Top level device name
        if device.product_id == 1:
            deviceid = 'Hub'
        else:
            deviceid = device.mac_address

        config.merge_update({'Devices': {parent_serial: {deviceid: device_result}}})

    for pet in data.pets:
        tag = [x for x in tags if x["id"] == pet.tag_id][0].tag
        log.debug("Adding Pet %s - %s", tag, pet.name)

        # Add Name and Species so the MDI Icon can be updated :)
        petresult = Box({'Name': pet.name, 'Species': pet.species_id if 'species_id' in pet else 0})

        if 'status' in pet:
            if 'activity' in pet.status:
                loc = ['', 'Inside', 'Outside']
                location = loc[pet.status.activity.where]
                petresult.merge_update({'Activity': {'Where': location, 'Time': pet.status.activity.since, 'Update_Mac':'0'}})
            if 'feeding' in pet.status:
                petresult.merge_update({'Feeding': {
                    'Change': pet.status.feeding.change, 'Time': pet.status.feeding.at}})
            if 'drinking' in pet.status:
                petresult.merge_update({'Drinking': {
                    'Change': pet.status.drinking.change, 'Time': pet.status.drinking.at}})
        config.merge_update({PET: {tag: petresult}})
    return config


def ha_init_entities(pethubconfig):
    """
        Build MQTT Messages for Home Assistant from current pethubconfig
    """
    mqtt_messages = Box()
    for hub, devices in Box(pethubconfig['Devices']).items():
        for device, attrs in devices.items():  # Devices
            # Device ID Value, either _Hub or _mac_address if it's not a hub
            if attrs.Product_Id == EntityType.Hub:
                devid = hub + '_Hub'
            else:
                devid = hub + '_' + attrs.Mac_Address

            # Generic Device info
            device_config = Box({
                'ids': attrs.Mac_Address,
                'name': attrs.Name,
                'sw': VERSION,
                'mdl': EntityType(attrs.Product_Id).name,
                'mf': 'Pet Hub Local'
            })

            # Create Battery sensor apart from hub as hubs don't have a battery
            if attrs.Product_Id != EntityType.Hub:
                config_message = Box({
                    'name': attrs.Name + ' Battery',
                    'ic': 'mdi:battery',
                    'uniq_id': devid + '_battery',
                    'stat_t': PH_HA_T + devid + '/state',
                    'val_tpl': '{{value_json.Battery}}',
                    'json_attr_t': PH_HA_T + devid + '/state',
                    'avty_t': PH_HA_T + devid + '/state',
                    'avty_tpl': '{{value_json.Availability}}',
                    'device': device_config})
                mqtt_messages.merge_update({HA_SENSOR + devid + '_battery/config': config_message.to_json()})

            # Device parameters
            if attrs.Product_Id == EntityType.Hub:
                icon = 'mdi:radio-tower'
            elif attrs.Product_Id in [EntityType.PetDoor, EntityType.CatFlap]:
                icon = 'mdi:door'
                # Switches for Doors
                lockstate = ['KeepIn', 'KeepOut', 'Curfew']
                for key in lockstate:
                    devidkey = devid + '_' + key.lower()
                    config_message = Box({
                        'name': attrs.Name + ' ' + pascal_to_spaced(key),
                        'ic': icon,
                        'uniq_id': devidkey,
                        'stat_t': PH_HA_T + devid + '/state',
                        'val_tpl': '{{value_json.' + key + '}}',
                        'json_attr_t': PH_HA_T + devid + '/state',
                        'cmd_t': PH_HA_T + devid + '/' + key,
                        'avty_t': PH_HA_T + devid + '/state',
                        'avty_tpl': '{{value_json.Availability}}',
                        'device': device_config
                    })
                    mqtt_messages.merge_update({
                        HA_SWITCH + devidkey + '/config': config_message.to_json()
                    })
                customModes = [
                    {"key": PetDoorCustomMode.NonSelective.name, "custIcon": "mdi:door-sliding-open"},
                    {"key": PetDoorCustomMode.Rechargeables.name, "custIcon": "mdi:battery"},
                    {"key": PetDoorCustomMode.ThreeSeconds.name, "custIcon": "mdi:timer-3"},
                    {"key": PetDoorCustomMode.TenSeconds.name, "custIcon": "mdi:timer-10"},
                    {"key": PetDoorCustomMode.Intruder.name, "custIcon": "mdi:shark-off"},
                    {"key": PetDoorCustomMode.OppositeCurfew.name, "custIcon": "mdi:clock-end"},
                    {"key": PetDoorCustomMode.LockedCurfew.name, "custIcon": "mdi:lock-clock"},
                    {"key": PetDoorCustomMode.MetalMode1.name, "custIcon": "mdi:shield"},
                    {"key": PetDoorCustomMode.MetalMode2.name, "custIcon": "mdi:shield-outline"},
                    {"key": PetDoorCustomMode.ExtendedRange.name, "custIcon": "mdi:signal"},
                    {"key": PetDoorCustomMode.ExtendedIntruder.name, "custIcon": "mdi:shark-off"},
                    {"key": PetDoorCustomMode.DoubleChip1.name, "custIcon": "mdi:chip"},
                    {"key": PetDoorCustomMode.DoubleChip2.name, "custIcon": "mdi:chip"},
                    {"key": PetDoorCustomMode.DoubleChip3.name, "custIcon": "mdi:chip"},
                    {"key": PetDoorCustomMode.ProximityTest.name, "custIcon": "mdi:radio-tower"}
                ]
                for mode in customModes:
                    key = mode["key"]
                    custIcon = mode["custIcon"]
                    devidkey = devid + '_' + key.lower()
                    config_message = Box({
                        'name': attrs.Name + ' Custom ' + pascal_to_spaced(key),
                        'ic': custIcon,
                        'uniq_id': devidkey,
                        'stat_t': PH_HA_T + devid + '/state',
                        'val_tpl': '{{value_json.Custom_Mode}}',
                        'json_attr_t': PH_HA_T + devid + '/state',
                        'cmd_t': PH_HA_T + devid + '/custom_mode',
                        'avty_t': PH_HA_T + devid + '/state',
                        'avty_tpl': '{{value_json.Availability}}',
                        'device': device_config
                    })
                    mqtt_messages.merge_update({
                        HA_SWITCH + devidkey + '/config': config_message.to_json()
                    })
            elif attrs.Product_Id == EntityType.Feeder:
                icon = 'mdi:bowl'
            elif attrs.Product_Id == EntityType.Poseidon:
                icon = 'mdi:glass-mug'
            else:
                icon = 'mdi:alien'

            config_message = Box({
                'name': attrs.Name,
                'ic': icon,
                'uniq_id': devid,
                'stat_t': PH_HA_T + devid + '/state',
                'val_tpl': '{{value_json.State}}',
                'json_attr_t': PH_HA_T + devid + '/state',
                'avty_t': PH_HA_T + devid + '/state',
                'avty_tpl': '{{value_json.Availability}}',
                'device': device_config,
            })
            mqtt_messages.merge_update({HA_SENSOR + devid + '/config': config_message.to_json()})

            if attrs.Product_Id in [EntityType.Feeder, EntityType.Poseidon]:
                # log.debug('HAINIT: %s - Add bowls %s', EntityType(attrs.Product_Id).Name, str(attrs.bowlcount))
                # Add separate sensors for the weights
                bowls = {
                    0: ['Weight'],
                    1: ['Weight'],
                    2: ['Left Weight', 'Right Weight']
                }
                if attrs.Bowl_Count in bowls:
                    for bowl in bowls[attrs.Bowl_Count]:
                        devidkey = devid + '_' + bowl.replace(' ', '_').lower()
                        # log.debug('HAINIT: %s - Add %s bowl "%s"', EntityType(attrs.Product_Id).Name, devidkey, bowl)
                        config_message = Box({
                            'name': attrs.Name + ' Current ' + bowl,
                            'ic': 'mdi:bowl',
                            'uniq_id': devidkey,
                            'stat_t': PH_HA_T + devid + '/state',
                            'val_tpl': '{{value_json["' + bowl + '"]}}',
                            'unit_of_meas': 'g',
                            'json_attr_t': PH_HA_T + devid + '/state',
                            'avty_t': PH_HA_T + devid + '/state',
                            'avty_tpl': '{{value_json.Availability}}',
                            'device': device_config,
                        })
                        mqtt_messages.merge_update({
                            HA_SENSOR + devidkey + '/config': config_message.to_json()
                        })

    for pet, attrs in Box(pethubconfig['Pets']).items():  # Pets
        pet_topic = pet.replace('.', '-').replace(' ', '_').lower()
        print('HAInit: Pet: ', pet, attrs)
        # Generic Device info
        pet_config = Box({
            'ids': pet_topic,
            'name': attrs.Name,
            'sw': 'v2.0',
            'mdl': Animal(int(attrs.Species)).name.title(),
            'mf': 'Pet Hub Local Pet'
        })
        config_message = Box({
            "name": attrs.Name,
            "icon": "mdi:" + Animal(int(attrs.Species)).name.lower(),
            "uniq_id": pet_topic,
            "stat_t": PH_HA_T + pet_topic + "/state",
            "json_attr_t": PH_HA_T + pet_topic + "/state",
            "val_tpl": "{{value_json.State}}",
            'device': pet_config
        })
        mqtt_messages.merge_update({HA_SENSOR + pet_topic + '/config': config_message.to_json()})
        if 'Feeding' in attrs:
            feeding_length = len(attrs.Feeding.Change)
            bowls = {
                0: ['Weight'],
                1: ['Weight'],
                2: ['Left Weight', 'Right Weight']
            }
            if feeding_length in bowls:
                for bowl in bowls[feeding_length]:
                    pet_topic_key = pet_topic + '_' + bowl.replace(' ', '_').lower()
                    config_message = Box({
                        'name': attrs.Name + ' Last Feed ' + bowl,
                        'ic': 'mdi:bowl',
                        "uniq_id": pet_topic_key,
                        'stat_t': PH_HA_T + pet_topic + "/state",
                        "val_tpl": "{{value_json['" + bowl + "']}}",
                        "unit_of_meas": "g",
                        'json_attr_t': PH_HA_T + pet_topic + '/state',
                        'device': pet_config
                    })
                    mqtt_messages.merge_update({
                        HA_SENSOR + pet_topic_key + '/config': config_message.to_json()
                    })
        if 'Drinking' in attrs:
            config_message = Box({
                'name': attrs.Name + ' Last Drink',
                'ic': 'mdi:glass-mug',
                "uniq_id": pet_topic + '_drinking',
                'stat_t': PH_HA_T + pet_topic + "/state",
                "val_tpl": "{{value_json.Drinking}}",
                "unit_of_meas": "g",
                'json_attr_t': PH_HA_T + pet_topic + '/state',
                'device': pet_config
            })
            mqtt_messages.merge_update({
                HA_SENSOR + pet_topic + '_drinking/config': config_message.to_json()
            })
    return mqtt_messages


def ha_update_state(pethubconfig, *devicepet):
    """ Update Home Assistant Device and Pet States """
    mqtt_messages = Box()
    for hub, devices in Box(pethubconfig['Devices']).items():
        for device, attrs in devices.items():  # Devices
            # log.debug('HA: State - Device %s Mac %s', device, attrs['mac_address'])
            if (not devicepet) or hub+'_'+device == devicepet[0]:
                # log.debug('HA: Hub %s Device %s', hub, device)
                # Device ID Value, either _Hub or _mac_address if it's not a hub
                if attrs.Product_Id == EntityType.Hub:
                    devid = hub + '_Hub'
                else:
                    devid = hub + '_' + attrs['Mac_Address']

                if attrs.Product_Id == EntityType.Hub:  # Hub
                    state_message = Box({
                        'Availability': attrs.State.lower() if 'State' in attrs else 'offline',
                        'State': attrs.State if 'State' in attrs else 'Offline',
                        'Uptime': str(attrs.Uptime if 'Uptime' in attrs else 0) + ' Mins',
                        'Name': attrs.Name,
                        'Reconnects': attrs.Reconnects if 'Reconnects' in attrs else '0',
                        'Serial': attrs.Serial_Number,
                        'MAC Address': attrs.Mac_Address,
                        'LED Mode': HubLeds(attrs.Led_Mode).name,
                        'Pairing Mode': HubAdoption(attrs.Pairing_Mode).name})
                    # version = Box.from_json(attrs.version)   # Loop version json blob and append
                    # for devs in version.device:
                    #     state_message[devs.title()] = version.device[devs]
                    mqtt_messages.merge_update({PH_HA_T + devid + '/state': state_message.to_json()})

                if attrs.Product_Id in [EntityType.PetDoor, EntityType.CatFlap]:  # Pet Door or Cat Flap
                    # Curfew state:
                    # Handling the dumb way that the Cat Flap has a curfew mode to toggle between
                    # enabled and the pet door goes to locking mode 4 for curfew.
                    if attrs.Product_Id == EntityType.PetDoor and attrs.Locking_Mode == LockState.CURFEW:
                        curfew = True
                    elif attrs.Product_Id == EntityType.CatFlap and attrs.Curfew_Enabled == 1:
                        curfew = True
                    else:
                        curfew = False

                    state_message = Box({
                        'Availability': attrs.State.lower() if 'State' in attrs else 'offline',
                        'State': (
                            "Keep In" if attrs.Locking_Mode == LockState.KEEPIN else # Make prettier on frontend
                            "Keep Out" if attrs.Locking_Mode == LockState.KEEPOUT else
                            LockState(attrs.Locking_Mode).name.title()
                        ),
                        'Battery': str(attrs.Battery),
                        'KeepIn': 'ON' if attrs.Locking_Mode in [LockState.KEEPIN, LockState.LOCKED] else 'OFF',
                        'KeepOut': 'ON' if attrs.Locking_Mode in [LockState.KEEPOUT, LockState.LOCKED] else 'OFF',
                        'Curfew': 'ON' if curfew else 'OFF',
                        'Curfews': str(attrs.Curfews)
                    })
                    if 'Custom_Modes' in attrs:
                        try:
                            custom_modes_str = attrs.Custom_Modes
                            custom_modes = ast.literal_eval(custom_modes_str)
                            log.debug(f"Parsed Custom Modes: {custom_modes}")
                        except Exception as e:
                            log.error(f"Error parsing Custom_Modes: {e}")
                            custom_modes = []
                        state_message.merge_update({"CustomMode": attrs.Custom_Modes})
                    mqtt_messages.merge_update({PH_HA_T + devid + '/state': state_message.to_json()})

                if attrs.Product_Id == EntityType.Feeder:
                    state_message = Box({
                        'Availability': attrs.State.lower() if 'State' in attrs else 'offline',
                        'State': attrs.Lid_State.title() if 'Lid_State' in attrs else 'Closed',
                        'Online': attrs.State if 'State' in attrs else 'Offline',
                        'Battery': str(attrs.Battery),
                        'Bowl Count': attrs.Bowl_Count,
                        'Close Delay': FeederCloseDelay(attrs.Close_Delay).name})
                    if attrs.Bowl_Count == 2:  # Two bowls
                        state_message.update({
                            'Left Target': str(attrs.Bowl_Target[0]),
                            'Right Target': str(attrs.Bowl_Target[1]),
                            'Left Weight': str(attrs.Bowl_Weight[0]),
                            'Right Weight': str(attrs.Bowl_Weight[1])
                        })
                    elif attrs.Bowl_Count == 1:  # One bowl
                        state_message.update({
                            'Target': str(attrs.Bowl_Target[0]),
                            'Weight': str(attrs.Bowl_Weight[0])
                        })
                    mqtt_messages.merge_update({PH_HA_T + devid + '/state': state_message.to_json()})

                if attrs.Product_Id == EntityType.Poseidon:  # Poseidon
                    state_message = Box({
                        'Availability': attrs.State.lower() if 'State' in attrs else 'offline',
                        'State': attrs.State.title() if 'State' in attrs else 'Offline',
                        'Battery': str(attrs.Battery),
                        'Weight': str(attrs.Bowl_Weight[0])})
                    mqtt_messages.merge_update({PH_HA_T + devid + '/state': state_message.to_json()})

    for pet, attrs in Box(pethubconfig['Pets']).items():  # Pets
        if len(devicepet) == 0 or pet == devicepet[0]:
            pet_topic = pet.replace('.', '-').replace(' ', '_').lower()
            pet_message = Box({})
            if 'Activity' in attrs:
                pet_message.merge_update({"State": attrs.Activity.Where})
                pet_message.merge_update({"Time": attrs.Activity.Time})
                pet_message.merge_update({"Update_Mac": attrs.Activity.Update_Mac})
            else:
                pet_message.merge_update({"State": "NoDoor"})
            if 'Feeding' in attrs:
                feeding_length = len(attrs.Feeding.Change) - 1
                bowls = {0: ['Weight'], 1: ['Left Weight', 'Right Weight']}
                if feeding_length in bowls:
                    for idx, bowl in enumerate(bowls[feeding_length]):
                        pet_message.merge_update({bowl: str(attrs.Feeding.Change[idx])})
            if 'Drinking' in attrs:
                pet_message.merge_update({"Drinking": str(attrs.Drinking.Change[0])})
            # log.info('Status: Pet Update %s - %s', pet, pet_message.to_json())
            mqtt_messages.merge_update({PH_HA_T + pet_topic + '/state': pet_message.to_json()})
    return mqtt_messages


def initdevices(pethubconfig, operations):
    """ Initialize Hub and connected devices on start with 'operations' """
    mqtt_messages = Box()
    for hub, devices in Box(pethubconfig['devices']).items():
        for device, attrs in devices.items():
            for operation in operations:
                # Loop operations and generate messages
                result = generatemessage(pethubconfig, hub, attrs.Product_Id, operation, mac=attrs['Mac_Address'])
                if 'error' not in result:
                    mqtt_messages.merge_update({operation: result})
    return mqtt_messages


def parse_mqtt_message(pethubconfig, mqtt_topic, mqtt_message):
    # Message from Hub, decode then return HA formatted messages
    offset = 2
    response = Box()
    if mqtt_topic.startswith(PH_HUB_T):  # Hub MQTT Message
        mqtt_topic_split = mqtt_topic.split('/')
        if len(mqtt_topic_split) > 2:
            message_split = mqtt_message.split()
            if message_split[1] != "1000":  # Don't process command messages that we have generated
                log.info('HUB: Inbound Message Topic: "%s" Message: "%s"', mqtt_topic, mqtt_message)
                update_watchdog();		# Update watchdog timestamp
                mqtt_messages = parse_hub(pethubconfig, mqtt_topic, mqtt_message)
                if 'message' in mqtt_messages:
                    for mqttmessage in mqtt_messages.message:
                        # Enrich payload with Animal name if known
                        if 'Tag' in mqttmessage:
                            pets = Box(pethubconfig[PET])
                            animals = []
                            for tag in mqttmessage.Tag:
                                if 'Empty' not in tag:
                                    if tag not in pethubconfig[PET]:  # Add missing pet
                                        print('Missing Pet')
                                        pets.merge_update({tag: {
                                            'Name': tag,
                                            'AutoAdded': True,
                                            'Species': 0}})
                                    animals.append(pets[tag]['Name'])  # Add name to Payload
                                    # Update config with current state
                                    if 'PetMovement' in mqttmessage.Operation:
                                        DeviceMac = str(mqtt_topic_split[-1])
                                        pets[tag]['Activity'] = {
                                            "Where": mqttmessage.Direction,
                                            "Time": timestamp_now(),
                                            "Update_Mac": DeviceMac}
                                    if 'Feed' in mqttmessage.Operation:
                                        pets[tag]['Feeding'] = {
                                            "Change": mqttmessage.Delta,
                                            "Time": timestamp_now()}
                                    if 'Drinking' in mqttmessage.Operation:
                                        pets[tag]['Drinking'] = {
                                            "Change": mqttmessage.Delta,
                                            "Time": timestamp_now()}
                            mqttmessage.merge_update({'Animals': animals})
                            pethubconfig[PET] = pets
                            config_save(pethubconfig)
                        if 'Update_State' in mqttmessage and mqttmessage.Update_State:
                            hamessage = Box()
                            if 'Update_Item' in mqttmessage and len(mqttmessage.Update_Item) > 0:
                                for item in mqttmessage.Update_Item:
                                    hamessage.merge_update(ha_update_state(pethubconfig, item))
                            else:
                                hamessage.merge_update(ha_update_state(pethubconfig, ))
                            log.debug('MQTT: Update HA State %s', hamessage.to_json())
                            mqtt_messages.merge_update({'HAMessage': hamessage})
                        if 'WebStatus' in mqttmessage and mqttmessage.WebStatus:
                            mqtt_messages.merge_update({'WebStatus': mqttmessage.WebStatus})
                        if 'Save_Config' in mqttmessage and mqttmessage.Save_Config:
                            mqtt_messages.merge_update({'Save_Config': mqttmessage.Save_Config})

                log.info('HUB: Parsed Enriched Message %s', json.dumps(mqtt_messages))
                response = mqtt_messages
            else:
                response = Box({'Message': 'Command message'})
        else:
            response = Box({'Message': 'Unknown Message'})

    if mqtt_topic.startswith(PH_HA_T):  # Home Assistant MQTT Message
        log.info('MQTT: HA Message topic "%s" message "%s" ', mqtt_topic, mqtt_message)
        splitmqtt_topic = mqtt_topic.split('/')
        deviceinfo = splitmqtt_topic[offset].split('_')
        hub = deviceinfo[0]
        mac = deviceinfo[1]
        dev = pethubconfig['Devices'][hub][mac]
        pid = dev['Product_Id']
        clm = dev["Locking_Mode"] if "Locking_Mode" in dev else 0  # Current Locking Mode
        nlm = clm  # New Locking Mode
        ccm = dev["Curfew_Enabled"] if "Curfew_Enabled" in dev else False  # Current Curfew Mode
        ncm = ccm  # New Curfew Mode
        op = splitmqtt_topic[offset + 1]
        result = []

        # Pet Door or Cat Flap
        if (pid in [3, 6] and op in ['KeepIn', 'KeepOut']) or (pid == 3 and op == 'Curfew'):
            # Pet door specific curfew operation
            if (pid == EntityType.PetDoor and op == 'Curfew' and mqtt_message == "ON"):
                nlm = LockState.CURFEW
                # Set Locking Mode
                result.append(generatemessage(pethubconfig, hub, pid, 'CURFEWS', mac=mac,
                                              suboperation=dev['Curfews']))
            # Going to Lock State 3 - Lock both ways
            elif (
                (clm == LockState.KEEPOUT and op == "KeepIn" and mqtt_message == "ON") or # Currently in KeepOut. Turning KeepIn on too will be full lock.
                (clm == LockState.KEEPIN and op == "KeepOut" and mqtt_message == "ON")    # Currently in KeepIn. Turning KeepOut on too will be full lock.
            ):
                nlm = LockState.LOCKED
            # Going to Lock State 2 - Keep pets out
            elif (
                (clm == LockState.LOCKED and op == "KeepIn" and mqtt_message == "OFF") or   # Currently in full lock. Removing KeepIn will be KeepOut.
                (clm == LockState.UNLOCKED and op == "KeepOut" and mqtt_message == "ON") or # Currently in unlocked. Turning KeepOut on will be KeepOut.
                (clm == LockState.CURFEW and op == "KeepOut" and mqtt_message == "ON")      # Currently in curfew. Turning KeepOut on will override Curfew and result in KeepOut.
            ):
                nlm = LockState.KEEPOUT
            # Going to Lock State 1 - Keep pets in
            elif (
                (clm == LockState.UNLOCKED and op == "KeepIn" and mqtt_message == "ON") or # Currently in unlocked. Turning KeepIn on will be KeepIn.
                (clm == LockState.LOCKED and op == "KeepOut" and mqtt_message == "OFF") or # Currently in full lock. Removing KeepOut will be KeepIn.
                (clm == LockState.CURFEW and op == "KeepIn" and mqtt_message == "ON")      # Currently in curfew. Turning KeepIn on will override Curfew and result in KeepIn.
            ):
                nlm = LockState.KEEPIN
            # Going to Lock State 0 - Unlocked
            else:
                nlm = LockState.UNLOCKED

            log.info("ToHub: Moving from current lock mode %s to lock mode %s",
                     LockState(clm).name, LockState(nlm).name)

            # Set Locking Mode
            result.append(generatemessage(pethubconfig, hub, pid, LockState(nlm).name, mac=mac,
                                          suboperation=dev['Curfews']))

        if pid == 6 and op == 'Curfew':
            if mqtt_message == "ON" and 'Curfews' in dev:
                log.info('Cat Flap Curfews %s', dev['Curfews'])
                result.append(generatemessage(pethubconfig, hub, pid, 'CURFEWS',
                                              mac=mac, suboperation=dev['Curfews']))
                dev['Curfew_Enabled'] = True
            else:
                result.append(generatemessage(pethubconfig, hub, pid, 'CURFEWS',
                                              mac=mac, suboperation=''))
                dev['Curfew_Enabled'] = False

        if len(result) > 0:
            response = Box({'Console': 'Going to locking mode: ' + LockState(nlm).name + ' On ' +
                                       deviceinfo[1] + ' ' + dev['Name'], 'HubMessage': result})
        else:
            response = Box({'Message': 'Error'})
        print(response)

    return response


def splitbyte(bytestring):
    """
     Convert hex string without spaces to have a space every second value
    """
    return " ".join(bytestring[i:i + 2] for i in range(0, len(bytestring), 2))


def int2bit(number, zfilllength):
    """ Integer String converted into binary string with zfilllength zero padding """
    return str(bin(int(number))[2:]).zfill(zfilllength)


def bltoi(value):
    """ Bytes little to integer """
    return int.from_bytes(value, byteorder='little')


def converttimetominutes(timearray):
    """ Seems that the minutes returned are in the upper byte, so need to subtract 128."""
    if timearray[1] >= 128:
        timearray[1] -= 128
    return str((timearray[0] * 60) + timearray[1])


def map_long_serial_key(long_serial_key):
    # log.debug('Long Serial Key - %s', "".join(long_serial_key.values()))
    return ''.join(list(map(long_serial_key.get, LONG_SERIAL_ORDER))).upper()


def parse_firmware_log(filename):
    """ Parse firmware update log and return password """
    if os.path.isfile(filename):
        with codecs.open(filename, 'r', encoding='utf-8', errors='ignore') as firmware:
            sn = ""
            long_serial_found = False
            long_serial_key = {}
            while True:
                line = firmware.readline()
                if not line:  # EOF
                    break
                if sn == "" and (line.startswith("serial_number=") or "As text:" in line):
                    snre = re.compile('H\d+-\d+')
                    sn = snre.findall(line)[0]
                    log.info("Serial Number: %s", sn)
                if long_serial_found:
                    if "length=1024" in line:
                        # Long Serial number footer.
                        long_serial = map_long_serial_key(long_serial_key)
                        log.info('Long Serial aka Certificate Password for %s : %s ', sn, long_serial )
                        return sn, long_serial
                    else:
                        if len(line) > 2:  # ignore blank lines
                            if line.startswith("10 "):
                                print("Corrupted file")
                                exit(1)
                            line_split = line.split()
                            # Pad zero to make a byte if it is a single character
                            long_serial_key[int(line_split[0], 16)] = line_split[1].zfill(2)
                if "Read " in line and " 1d000000 1000 1" in line and long_serial_found == False:
                    # Long Serial number header found.
                    log.info("Long Serial Header Found")
                    long_serial_found = True
        firmware.close()
    else:
        log.info('File not found')


def find_firmware_xor_key(serial_number, boot_loader):
    """
      Firmware records have a 36 byte header and double XORed key. The header has 6 values delimited with a space
      - CRC16 - 2 Bytes
      - Memory Offset to wipe(?) - 4 Bytes
      - Record count - 2 Bytes in hex
      - Memory Offset to write firmware to
      - Record length
      - Always 01
      The trick with finding the XOR Key is the key length is 16 bytes, and the most frequently used value in the deXORed
      firmware is typically all 0's so if you split the PFM firmware into 16 byte chunks and add them all into a key pair
      dict then find the most frequent value that is the XOR key.

      Thanks Toby for figuring this one out, you are a **superstar**!!
    """
    # PFM Record Count, 3rd field in hex
    with open(f'{serial_number}-{boot_loader}-00.bin', 'rb') as f:
        header = f.read(36).decode("utf-8").split()
        record_count = int(header[2], 16)
        log.info('Firmware XOR: Record Count - %s', str(record_count))
        # if firmware == '319a'

    # Create pairs finding breaking it into 16 bytes which is the XOR key size.
    key = {}
    for record in range(0, record_count):
        with open(f'{serial_number}-{boot_loader}-{str(record).zfill(2)}.bin', 'rb') as file:
            file.seek(36)  # Skip header
            firmware_hex = file.read().hex()
            if len(firmware_hex) == 8192:
                while len(firmware_hex) > 1:
                    record = firmware_hex[:32]  # XOR is 16 bytes
                    firmware_hex = firmware_hex[32:]  # Remove 16 bytes from hex
                    if record in key:
                        key[record] += 1  # Has existing record
                    else:
                        key[record] = 1  # New record

    # Find XOR key in key array, most frequent value in deXORed file is all 0's so that is the key.
    xor_key = bytes.fromhex(sorted(key, key=key.get, reverse=True)[0])
    log.info('Firmware XOR: Found XOR Key - %s', xor_key.hex().upper())

    # XOR with Found XOR Key and Static XOR Key to find Long Key for Long Serial
    long_serial_key = bytes(x ^ y for x, y in zip(xor_key, FIRMWARE_STATIC_XOR_KEY))
    log.info('Firmware XOR: Long Serial Key - %s', long_serial_key.hex().upper())

    # Convert to Bytes to Dict as it's just easier to use map.
    long_serial_dict = {i: f'{long_serial_key[i]:0x}'.zfill(2) for i in range(0, len(long_serial_key))}
    long_serial = map_long_serial_key(long_serial_dict)

    log.info('Firmware XOR: Long Serial aka Certificate Password - %s', long_serial)

    return xor_key.hex().upper(), long_serial


def build_firmware(xor_key, serial_number):
    """
      Build firmware based on known/found XOR key and name the files after serial_number
    """
    firmware = f'{serial_number}-{FIRMWAREVERSION}-00.bin'
    if not os.path.isfile(firmware):
        log.info('Firmware: Building version %s firmware', str(FIRMWAREVERSION))
        package_dir = files("pethublocal") / "firmware"
        # Find the number of records / pages based on FIRMWAREVERSION
        with open(f'{package_dir}/Firmware-{FIRMWAREVERSION}-00.bin', 'rb') as f:
            headersplit = f.read(36).decode("utf-8").split()
            record_count = int(headersplit[2], 16)

        # Handle if we pass the XOR Key as a string
        if isinstance(xor_key, str):
            xor_key = bytes.fromhex(xor_key)
        # Encrypting firmware with XOR key for serial number PFM, DCR and BFM
        for record in range(0, record_count + 6):
            with open(f'{package_dir}/Firmware-{FIRMWAREVERSION}-{str(record).zfill(2)}.bin', 'rb') as file:
                header = file.read(36)
                firmware_hex = file.read().hex()
                payload = bytes()

                # Reapply XOR to this serial number firmware file
                while len(firmware_hex) > 1:
                    current_record = bytes.fromhex(firmware_hex[:32])
                    payload += bytes(x ^ y for x, y in zip(xor_key, current_record))
                    firmware_hex = firmware_hex[32:]

                with open(f'{serial_number}-{FIRMWAREVERSION}-{str(record).zfill(2)}.bin', 'wb') as to_file:
                    to_file.write(header + payload)
                    to_file.close()
        log.info('Firmware: Custom firmware built')
    else:
        log.info('Firmware %s already exists', firmwares)




def update_watchdog():
    global LastMessageFromHub
    LastMessageFromHub = datetime.utcnow()    # Init Watchdog timestamp
    log.debug('Watchdog timer was reset')

def get_watchdog():
    global LastMessageFromHub
    TimeDifference = datetime.utcnow() - LastMessageFromHub
    return TimeDifference.seconds

