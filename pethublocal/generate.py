"""
   Generate Sure Pet Packet
   Copyright (c) 202s, Peter Lambrechtsen (peter@crypt.nz)
"""
import re

from datetime import date, datetime, timezone
from dateutil import tz
from box import Box

# Shared Functions
from .enums import *
from .consts import (
    PH_HUB_T,
    DEV
)
from . import log


def hex_spaces(ba):
    return " ".join("{:02x}".format(x) for x in ba)


def dt_to_hub_ts(n):
    """ Convert Datetime object into pet hub device hex. """
    bintime = f"{int(n.strftime('%y')):06b}{n.month:04b}{n.day:05b}{n.hour:05b}{n.minute:06b}{n.second:06b}"
    return hex_spaces(int(bintime, 2).to_bytes(4, 'little'))  # Return as a little hex string
    # return int(bintime, 2).to_bytes(4, 'little').hex(' ')  # Return as a little hex string


def hours_to_dt(hours):
    local_datetime = datetime.strptime(hours, '%H:%M').time()
    return datetime.combine(date.today(), local_datetime).astimezone(tz.tzutc())


def tag_to_hex(tag):
    """
     Convert Tag to Hex String with spaces to send to devices devices (not Pet Door)
    """
    if "." in tag:
        # FDX-B tag - Append 01 for tag type.
        # Create int list from split of tag
        tag_split = list(map(int, tag.split(".")))
        # Then create a hex string int list making binary zero padding of 10 and 38 bits and append the type 01.
        tag_hex = int(f"{tag_split[0]:010b}{tag_split[1]:038b}", 2).to_bytes(6, 'little').hex() + '01'
    elif len(tag) == 10:
        # HDX tag - tag type seems to be always 03 and needs a 00 to pad it to the right length.
        tag_hex = tag+'0003'
    else:
        # Something is broken and this should never happen but lets return 14 zero's
        tag_hex = "0" * 14
    return hex_spaces(bytearray.fromhex(tag_hex))
    # return bytearray.fromhex(tag_hex).hex(' ')


def door_tag_to_hex(tag):
    """
     Convert Tag to Hex String with spaces for Pet Door
    """
    if "." in tag:
        # FDX-B tag - Prepend 01 for tag type.
        # Create int list from split of tag
        tag_split = list(map(int, tag.split(".")))
        # Then create a hex string prepend 01 for FDX-B
        # Tag is binary string with 10 bits and 38 bits zero padded, reverse it, into big endian bytes.
        tag_hex = '01' + int(f"{tag_split[0]:010b}{tag_split[1]:038b}"[::-1], 2).to_bytes(6, byteorder='big').hex()
    # elif len(tag) == 10:  ** TODO Need to figure out how the HDX tags are calculated
    #     # HDX tag - tag type seems to be always 04.
    #     tag_hex = '04' + tag
    else:
        # Something is broken and this should never happen but lets return 7 bytes of zero's
        tag_hex = "0" * 14
    return hex_spaces(bytearray.fromhex(tag_hex))
    # return bytearray.fromhex(tag_hex).hex(' ')


def buildmqttsendmessage(value):
    """ Create standard hex UTC timestamp prefix plus 1000 for command message and value passed for the hub """
    return hex(round(datetime.utcnow().timestamp()))[2:] + " 1000 " + value


def generatemessage(pethubconfig, hub, product_id, operation, **genmsg):
    """ Generate message """
    log.debug('Generate Message Hub:%s Product:%s, Operation:%s', hub, str(product_id), operation)
    has_error = False
    result = None
    error = None
    operationupper = operation.upper()
    if 'mac' in genmsg:
        mac = genmsg['mac']
    if 'suboperation' in genmsg:
        suboperation = genmsg['suboperation']
    else:
        suboperation = ''

    # Add device variable
    if product_id != 1 and 'mac' in genmsg and genmsg['mac'] in pethubconfig['Devices'][hub]:
        device = pethubconfig[DEV][hub][genmsg['mac']]
    else:
        device = pethubconfig[DEV][hub]['Hub']

    if product_id == 1:  # Hub
        operations = Box({
            "DumpRegisters": {"msg": "3 0 205",   "desc": "Dump current configuration"},                    # Dump all memory registers from 0 to 205
            "Adopt":         {"msg": "2 15 1 02", "desc": "Enable adoption mode to adopt devices."},        # Enable adoption mode to adopt new devices
            "AdoptDisable":  {"msg": "2 15 1 00", "desc": "Disable adoption mode"},                         # Disable adoption mode
            "AdoptButton":   {"msg": "2 15 1 82", "desc": "Enable adoption using reset button."},           # Enable adoption mode as if you pressed the button under the hub
            "EarsOff":       {"msg": "2 18 1 00", "desc": "Ears off"},                                      # Ears off state
            "EarsOn":        {"msg": "2 18 1 01", "desc": "Ears on"},                                       # Ears on state
            "EarsDimmed":    {"msg": "2 18 1 04", "desc": "Ears dimmed"},                                   # Ears dimmed state
            "FlashEarsOff":  {"msg": "2 18 1 80", "desc": "Flash ears 3 times and return to ears off"},     # Flash the ears 3 times, return to off state
            "FlashEarsOn":   {"msg": "2 18 1 81", "desc": "Flash ears 3 times and return to ears on"},      # Flash the ears 3 times, return to on state
            "FlashEarsDim":  {"msg": "2 18 1 84", "desc": "Flash ears 3 times and return to ears dimmed"},  # Flash the ears 3 times, return to dimmed state
            "RemoveDev0":    {"msg": "2 22 1 00", "desc": "Remove Provisioned device 0"},                   # Remove Provisioned device 0
            "RemoveDev1":    {"msg": "2 22 1 01", "desc": "Remove Provisioned device 1"},                   # Remove Provisioned device 1
            "RemoveDev2":    {"msg": "2 22 1 02", "desc": "Remove Provisioned device 2"},                   # Remove Provisioned device 2
            "RemoveDev3":    {"msg": "2 22 1 03", "desc": "Remove Provisioned device 3"},                   # Remove Provisioned device 3
            "RemoveDev4":    {"msg": "2 22 1 04", "desc": "Remove Provisioned device 4"},                   # Remove Provisioned device 4
            "RemoveDev5":    {"msg": "2 22 1 05", "desc": "Remove Provisioned device 5"},                   # Remove Provisioned device 5
            "RemoveDev6":    {"msg": "2 22 1 06", "desc": "Remove Provisioned device 6"},                   # Remove Provisioned device 6
            "RemoveDev7":    {"msg": "2 22 1 07", "desc": "Remove Provisioned device 7"},                   # Remove Provisioned device 7
            "RemoveDev8":    {"msg": "2 22 1 08", "desc": "Remove Provisioned device 8"},                   # Remove Provisioned device 8
            "RemoveDev9":    {"msg": "2 22 1 09", "desc": "Remove Provisioned device 9"}                    # Remove Provisioned device 9
        })
        if operation == "operations":
            result = operations
        elif operation in operations:
            result = Box({PH_HUB_T + hub + "/messages": buildmqttsendmessage(operations[operation].msg)})
        else:
            result = Box({"error": "Unknown message"})

    elif product_id == 3:  # Pet Door
        operations = Box({
            "DUMPREGISTERS": {"msg": "3 0 630",                     "desc": "Dump current registers"},                # Dump all memory registers from 0 to 630
            "GETBATTERY":    {"msg": "3 33 1",                      "desc": "Get Battery"},                           # Get Battery State
            "GETPROV":       {"msg": "3 59 2",                      "desc": "Get Prov Tags"},                         # Get Prov Tags
            "GETSLOT":       {"msg": "3 60 1",                      "desc": "Get Slot Info"},                         # Get Slot Info
            "GETTAG":        {"msg": "3 91 35",                     "desc": "Get Tag"},                               # Get Prov Tags
            "GETCURFEW":     {"msg": "3 519 6",                     "desc": "Get Prov Tags"},                         # Get Prov Tags
            "SETTIME":       {"msg": "2 34 2 HH MM",                "desc": "Set the time"},                          # Set the time on the pet door HH MM in hex
            "CUSTOMMODE":    {"msg": "2 61 3 CM CM CM",             "desc": "Set Custom mode"},                       # Set custom mode as a bit operator
            "UNLOCKED":      {"msg": "2 36 1 00",                   "desc": "Unlocked"},                              # Unlocked
            "KEEPIN":        {"msg": "2 36 1 01",                   "desc": "Keep pets in"},                          # Keep Pets in
            "KEEPOUT":       {"msg": "2 36 1 02",                   "desc": "Keep pets out"},                         # Keep Pets out
            "LOCKED":        {"msg": "2 36 1 03",                   "desc": "Locked both way"},                       # Locked both ways
            "CURFEW":        {"msg": "2 36 1 04",                   "desc": "Curfew enabled"},                        # Curfew mode enabled
            "LOCKSTATE39":   {"msg": "2 39 1 01",                   "desc": "Lock State 39"},                         # Not sure if this is needed, but it was set once during set locking state.
            "TAGPROVISION":  {"msg": "2 II 7 CC CC CC CC CC CC CC", "desc": "TAG Provision"},                         # Tag Provision
            "CURFEWS":       {"msg": "2 519 6 SS FF FF TT TT 00",   "desc": "Set Curfew time From / To"},             # Enable curfew time from database
        })
        if operationupper in operations:
            message = operations[operationupper].msg

            if "HH MM" in message:  # Set the time
                now = datetime.now()  # Current local time
                message = message.replace('HH MM', f'{now.hour:02x} {now.minute:02x}')  # Time in hex

            # Custom Mode
            if "CM CM CM" in message:
                if PetDoorCustomMode.has_member(suboperation.title()):
                    customvalue = PetDoorCustomMode[suboperation.title()].value
                    print('Custom', type(customvalue), customvalue)
                    # if customvalue != 0:
                    #     currentcustom = PetDoorCustomMode(device['Custom_Mode'] if 'Custom_Mode' in device else 0)
                    #     # finalcustom = currentcustom | customvalue
                    device.merge_update({'Custom_Mode': customvalue})
                    # pethubconfig['Devices'] = devices
                    print('Custom2',customvalue.to_bytes(3, 'big').hex())
                    message = message.replace("CM CM CM", customvalue.to_bytes(3, 'big').hex(' '))
                else:
                    has_error = True
                    error = Box({"error": "Invalid custom mode passed " + str(suboperation)})

            if "SS FF FF TT TT" in message:  # Update Curfews
                log.debug('Updating Curfews')
                # Set Curfew Time
                if 'curfews' in genmsg:
                    curfews = genmsg['curfews']
                elif 'Curfews' in device:
                    curfews = device['Curfews']
                # curfewsstartstop = curfews.split('-')
                curfewsarray = re.split('-| |:', curfews)
                # Set the curfew time
                message = message.replace('FF FF TT TT', bytearray([int(x) for x in curfewsarray]).hex(' '))

                # Set Curfew State
                if 'curfewenabled' in genmsg:
                    curfewenabled = genmsg['curfewenabled']
                elif 'Curfew_Enabled' in device:
                    curfewenabled = device['Curfew_Enabled']
                if curfewenabled is True or curfewenabled == 'ON':
                    message = message.replace("SS", f"{CurfewState['ON'].value:02x}")
                else:
                    message = message.replace("SS", f"{CurfewState['OFF'].value:02x}")

            if "CC CC CC CC CC CC CC" in message:  # Update Tag Provisioning
                # Tag Offset
                if 'offset' in genmsg:
                    offset = (int(genmsg['offset']) * 7) + 91
                    # print('tag offset', offset)
                    message = message.replace('II', f"{offset}")
                else:
                    message = message.replace('II', '00')
                # Tag to Hex
                if 'tag' in genmsg:
                    message = message.replace('CC CC CC CC CC CC CC', door_tag_to_hex(genmsg['tag']))
                else:
                    message = message.replace('CC CC CC CC CC CC CC', '00 00 00 00 00 00 07')


            result = Box({PH_HUB_T + hub + "/messages/" + mac: buildmqttsendmessage(message)})
        else:
            result = Box({"error": "Unknown message"})


    elif product_id in [4, 6, 8]:  # CatFlap, Feeder or Poseidon
        """
            All messages detected sending to the feeder, if the fields have validation then they have a validate date referencing the above dictionary key value pairs

            Common Messages across all devices
            ACK - Send acknowledge to data type
            GET - Get data type state
            GETBATTERY - Get Battery state
            SETTIME - Set device time, seems like the last byte = 04 sets time when going forward, 05 sets time, 06 sets time on boot
            TAGPROVISION - Provision or enable or disable chip

            Feeder specific messages
            SETLEFTSCALE - Set left or single scale weight in grams to 2 decimal places
            SETRIGHTSCALE - Set right scale weight in grams to 2 decimal places
            SETBOWLCOUNT - Set bowl count either 01 for one bowl or 02 for two.
            SETCLOSEDELAY - Set lid close delay, 0 (fast) , 4 seconds (normal), 20 seconds (slow)
            ZEROSCALE - Zero left right or both scales
            SET12 - Not sure what caused this but it happened around setting the scales
            CUSTOMMODE - Custom modes, refer to const for the modes

            Cat Flap specific messages
            UNLOCKED - Unlocked
            KEEPIN - Keep Pets in
            KEEPOUT - Keep Pets out
            LOCKED - Locked both ways
            CURFEWS - Set Curfew mode to enabled. Different from Pet Door Curfews as the cat flap it's additive

            Poseidon specific messages - There isn't much as all that can be done is adding tags.
            ADDTAG - Enable adding Tag
            ENDADDTAG - Disable adding Tag
        """
        ackdatatype = Box({
            "Time":        "07",  # Time
            "Config":      "09",  # Config message
            "Unknown0b":   "0b",  # Unknown 0b message
            "Battery":     "0c",  # Battery state change
            "LockState":   "0d",  # CatFlap Lock State and Zero Scales
            "Boot10":      "10",  # Boot message 10
            "Tags":        "11",  # Tag provisioning
            "Curfew":      "12",  # Curfew
            "PetMovement": "13",  # Pet movement in / out cat flap
            "Custom":      "14",  # Feeder Custom Mode
            "Status16":    "16",  # Status 16 message, happens each time feeder manually opened
            "Boot17":      "17",  # Boot message 17
            "Feeder":      "18",  # Feeder state change
            "Poseidon":    "1b",  # Poseidon drinking from bowl
        })

        getdatatype = Box({
            "Boot9":     "09 00 ff",  # Boot message 09
            "Boot10":    "10 00",     # Boot message 10
            "Tags":      "11 00 ff",  # Tag provisioned
            "Curfew":    "12 00",     # Curfew state
            "Boot17":    "17 00 00",  # Boot message  17
            "Unknown0b": "0b 00",     # Unknown 0b
            "Battery":   "0c 00",     # Battery state
            "LockState": "0d 00",     # Lock state
            "Water":     "1b 00",     # Water state
        })

        # Feeder
        bowlcount = Box({
            "One": "01",  # One bowl
            "Two": "02",  # Two bowls
        })
        zeroscale = Box({
            "Left":  "01",  # Zero left scale
            "Right": "02",  # Zero right scale
            "Both":  "03",  # Zero both scale
        })

        operations = Box({
            "ACK":              {"msg": "127 00 00 ZZ ZZ TT TT TT TT SS 00 00",                      "desc": "Send acknowledge to data type", "validate": ackdatatype},
            "GET":              {"msg": "127 01 00 ZZ ZZ TT TT TT TT SS",                            "desc": "Get current state of data type", "validate": getdatatype},
            "GETBATTERY":       {"msg": "127 01 00 ZZ ZZ TT TT TT TT 0c 00",                         "desc": "Get current state of data type"},
            "SETTIME":          {"msg": "127 07 00 ZZ ZZ TT TT TT TT 00 00 00 00 07",                "desc": "Set the device time"},
            "TAGPROVISION":     {"msg": "127 11 00 ZZ ZZ TT TT TT TT CC CC CC CC CC CC CC KK II SS", "desc": "Provision/enable or disable chip"},

            # Feeder
            "SETLEFTSCALE":     {"msg": "127 09 00 ZZ ZZ TT TT TT TT 0a WW WW WW WW",                       "desc": "Set the left or single scale target weight"},
            "SETRIGHTSCALE":    {"msg": "127 09 00 ZZ ZZ TT TT TT TT 0b WW WW WW WW",                       "desc": "Set the right scale target weight"},
            "SETBOWLCOUNT":     {"msg": "127 09 00 ZZ ZZ TT TT TT TT 0c SS 00 00 00",                       "desc": "Set the bowl count", "validate": bowlcount},
            "SETCLOSEDELAY":    {"msg": "127 09 00 ZZ ZZ TT TT TT TT 0d LL LL LL LL",                       "desc": "Set the lid close delay"},
            "ZEROSCALE":        {"msg": "127 0d 00 ZZ ZZ TT TT TT TT 00 19 00 00 00 03 00 00 00 00 01 SS",  "desc": "Zero the scales left/right/both", "validate": zeroscale},
            "SET12":            {"msg": "127 09 00 ZZ ZZ TT TT TT TT 12 f4 01 00 00",                       "desc": "Set the 12 message"},
            "CUSTOMMODE":       {"msg": "127 09 00 ZZ ZZ TT TT TT TT 14 CM CM CM CM",                       "desc": "Set Custom Mode"},

            # Cat Flap
            "UNLOCKED":         {"msg": "127 11 00 ZZ ZZ TT TT TT TT 00 00 00 00 00 00 07 06 00 02",    "desc": "Unlocked"},
            "KEEPIN":           {"msg": "127 11 00 ZZ ZZ TT TT TT TT 00 00 00 00 00 00 07 03 00 02",    "desc": "Keep pets in"},
            "KEEPOUT":          {"msg": "127 11 00 ZZ ZZ TT TT TT TT 00 00 00 00 00 00 07 05 00 02",    "desc": "Keep pets out"},
            "LOCKED":           {"msg": "127 11 00 ZZ ZZ TT TT TT TT 00 00 00 00 00 00 07 04 00 02",    "desc": "Locked both way"},
            "CURFEWS":          {"msg": "127 12 00 ZZ ZZ TT TT TT TT 00 00 00 00 00 00 07 00 AA",       "desc": "Set Curfew"},

            # Poseidon
            "ADDTAG":           {"msg": "127 09 00 ZZ ZZ TT TT TT TT 0f 01 00 00 00",                    "desc": "Add Tag"},
            "ENDADDTAG":        {"msg": "127 09 00 ZZ ZZ TT TT TT TT 0f 00 00 00 00",                    "desc": "End Add Tag"},

        })
        if operationupper in operations:
            message = operations[operationupper].msg
            # This operation has values we should validate
            if "validate" in operations[operationupper]:
                if 'suboperation' in genmsg:
                    if suboperation in operations[operationupper].validate:  # Has string value to map
                        message = message.replace("SS", operations[operationupper].validate[suboperation])
                    elif suboperation in operations[operationupper].validate.values():  # Has value in validation dictionary
                        message = message.replace("SS", suboperation)
                    elif f'{int(suboperation):02x}' in operations[operationupper].validate.values():  # Has value in validation dictionary
                        message = message.replace("SS", f'{int(suboperation):02x}')
                    else:
                        has_error = True
                        error = Box({"error": "Invalid value passed, check validation", "validate": operations[operationupper].validate})

            # Tag Provisioning
            if "CC CC CC CC CC CC CC" in message:
                # Tag Offset
                if 'offset' in genmsg:
                    message = message.replace('II', f"{int(genmsg['offset']):02x}")
                else:
                    message = message.replace('II', '00')
                # Tag to Hex
                if 'tag' in genmsg:
                    message = message.replace('CC CC CC CC CC CC CC', tag_to_hex(genmsg['tag']))
                else:
                    message = message.replace('CC CC CC CC CC CC CC', '00 00 00 00 00 00 07')
                # Set Lock State for Tag either Normal or Keep In, default to Normal
                if 'lockstate' in genmsg and CatFlapLockState.has_member(genmsg['lockstate'].upper()):
                    message = message.replace("KK", f"{CatFlapLockState[genmsg['lockstate'].upper()].value:02x}")
                else:
                    message = message.replace("KK", '02')
                # Set Tag State to Enable / Disable, default to enabled
                if 'tagstate' in genmsg and TagState.has_member(genmsg['tagstate'].upper()):
                    message = message.replace("SS", f"{TagState[genmsg['tagstate'].upper()].value:02x}")
                else:
                    message = message.replace("SS", '00')

            # Custom Mode
            if "CM CM CM CM" in message:
                if isinstance(suboperation, str) and FeederCustomMode.has_member(suboperation):
                    message = message.replace("CM CM CM CM", hex_spaces(FeederCustomMode[suboperation].to_bytes(4, 'little')))
                    # message = message.replace("CM CM CM CM", FeederCustomMode[suboperation.upper()].to_bytes(4, 'little').hex(' '))
                elif isinstance(suboperation, int) or suboperation.isdigit():
                    message = message.replace("CM CM CM CM", hex_spaces(FeederCustomMode(int(suboperation)).to_bytes(4, 'little')))
                    # message = message.replace("CM CM CM CM", FeederCustomMode(int(suboperation)).to_bytes(4, 'little').hex(' '))
                else:
                    has_error = True
                    error = Box({"error": "Invalid custom mode passed " + str(suboperation)})

            # ** Feeder **
            # Message has a weight value we need to convert from the incoming state
            if "WW WW WW WW" in message:
                if suboperation.isdigit():
                    weight = hex_spaces((int(suboperation)*100).to_bytes(4, 'little'))
                    # weight = (int(suboperation)*100).to_bytes(4, 'little').hex(' ')
                    message = message.replace("WW WW WW WW", weight)
                else:
                    has_error = True
                    error = Box({"error": "No valid positive integer weight passed"})

            # Lid Close Delay speed
            if "LL LL LL LL" in message:
                if FeederCloseDelay.has_member(suboperation.upper()):
                    message = message.replace("LL LL LL LL", FeederCloseDelay[suboperation.upper()].as_hex())
                else:
                    has_error = True
                    error = Box({"error": "No valid lid close delay passed"})

            # Set Curfew - There can be 4 curfew times, and if they are unset then the second for loop applies.
            if "AA" in message:
                curfewcount = 0
                curfewmessage = ""
                if suboperation and len(suboperation) > 1:
                    suboperationsplit = suboperation.split(',')
                    for cur in suboperationsplit:
                        startendsplit = cur.split('-')
                        # Time is in UTC using the Cat Flap timestamp format with 00 seconds.
                        # start = datetime.strptime(startendsplit[0], '%H:%M').time()
                        # end = datetime.strptime(startendsplit[1], '%H:%M').time()
                        # startdatetime = datetime.combine(date.today(), start).astimezone(tz.tzutc())
                        # enddatetime = datetime.combine(date.today(), end).astimezone(tz.tzutc())
                        curfewmessage += dt_to_hub_ts(hours_to_dt(startendsplit[0])) + " "
                        curfewmessage += dt_to_hub_ts(hours_to_dt(startendsplit[1])) + " 03"
                        # 03 for enabled after the two times.
                        if curfewcount < 3:
                            curfewmessage += " "
                        curfewcount += 1
                    # Curfews suck on the cat door, there is no way to detect if curfews is enabled or not
                    device['Curfew_Enabled'] = True
                else:
                    device['Curfew_Enabled'] = False
                for i in range(curfewcount, 4):  # Set the remaining curfews to disabled
                    curfewmessage += "00 00 42 00 00 00 42 00 06"
                    if i < 3:
                        curfewmessage += " "
                message = message.replace("AA", curfewmessage)  # Update the payload with the curfew message

            # Get Device Counter and update
            devices = pethubconfig[DEV]
            counter = devices[hub][mac]['Send_Counter'] + 1
            if counter > 65534:
                counter = 0
            devices[hub][mac]['Send_Counter'] = counter

            message = message.replace('ZZ ZZ', hex_spaces(counter.to_bytes(2, 'little')))
            pethubconfig[DEV] = devices

            # Update timestamp
            utctime = datetime.utcnow()  # Current timestamp in UTC
            # Replace timestamp in the record
            message = message.replace('TT TT TT TT', dt_to_hub_ts(utctime))
            result = Box({PH_HUB_T + hub + '/messages/' + mac: buildmqttsendmessage(message)})

        else:
            has_error = True
            error = Box({"error": "Unknown message"})

    else:
        has_error = True
        error = Box({'error': 'Unknown type'})
    res = result
    if has_error:
        res = error
    return res
