#!/usr/bin/env python3
"""
   Decode Sure Pet Packet
   Inbound MQTT frame from the hub and convert it into a Python Box aka JSON that is human readable
   Copyright (c) 2021, Peter Lambrechtsen (peter@crypt.nz)
"""
import math
from bisect import bisect
from dateutil import tz
from box import Box
from datetime import datetime, timedelta
import json
from .consts import *
from .enums import *
from .generate import generatemessage
from . import log

DEBUGRESPONSE = False

# Shared Functions
def devicetimestamp(hexts, time_zone, tz_format):
    """
     Convert device hex timestamp into something human readable
    """
    timestamp_int = int.from_bytes(hexts, byteorder='little')
    year = int(f'20{timestamp_int >> 26:02}')  # Year - 6 Bits, prepending 20 for 4 digit year
    month = timestamp_int >> 22 & 0xf          # Month - 4 Bits
    day = timestamp_int >> 17 & 0x1f           # Day - 5 Bits
    hour = timestamp_int >> 12 & 0x1f          # Hour - 5 Bits
    minute = timestamp_int >> 6 & 0x3f         # Minute - 6 Bits
    second = timestamp_int & 0x3f              # Second - 6 Bits

    if year == 2000:
        result = f'{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}'
    else:
        if tz_format == '':
            ts_fmt = '%Y-%m-%d %H:%M:%S'
        else:
            ts_fmt = tz_format
        utc_ts = datetime(year,month,day,hour,minute,second).replace(tzinfo=tz.tzutc())
        if time_zone == 'Local':
            result = utc_ts.astimezone().strftime(ts_fmt)
        else:
            result = utc_ts.strftime(ts_fmt)
    return result


def timestampastime(timestamp):
    """ Convert Timestamp to HH MM"""
    return timestamp.strftime('%H:%M')


def converttime(timearray):
    """ Seems that the minutes returned are in the upper byte, so need to subtract 128. """
    if timearray[1] >= 128:
        timearray[1] -= 128
    return ':'.join(format(x, '02d') for x in timearray)


def hex_to_tag(tagbytes):
    """ Convert Device Hex to Tag """
    result = 'Empty'
    if len(tagbytes) == 7:
        if tagbytes[6] == 0x01:  # FDX-B tag type 0x01
            # 48 bit / 6 bytes little endian hex value for the tag
            tag_int = int.from_bytes(tagbytes[:6], byteorder='little')
            if tag_int > 0:
                # Country Code  - 10 Bits
                # National Code - 38 Bits zero padded to 12 digits
                result = f'{tag_int >> 38}.{tag_int & 0x3fffffffff:012}'
        elif tagbytes[6] == 0x03:  # HDX Tag type 0x03
            # First 5 bytes of hex is the HDX Tag
            result = tagbytes[:5].hex()
        # elif tagbytes[6] == 0x07:  # Empty Tag 0x07
        # elif tagbytes[6] == 0x00:  # Empty Tag 0x00
    else:
        result = tagbytes.hex()
    return result


def door_hex_to_tag(taghex):
    """ Convert Pet Door hex string to Tag Value """
    result = "Empty"
    if len(taghex) == 7 and taghex[0] == 0x01:  # FDX-B Tag
        # Big endian, into binary, then reverse string and then convert to int
        tagint = int(f"{int.from_bytes(taghex[1:], byteorder='big'):048b}"[::-1], 2)
        # Same function as all other devices with bitwise int to string
        result = f'{tagint >> 38}.{tagint & ~0xffc000000000:012}'
    # elif len(taghex) == 7 and taghex[0] == 0x04:  # HDX Tag
    #     chip = "Null"  # **TODO Need to figure out how to calculate this
    # else:
    return result


def b2iu(value):
    """ Little endian hex byte array and convert it into an unsigned int then into a string. """
    return str(int.from_bytes(value, byteorder='little', signed=False))


def b2is(value):
    """ Little endian hex byte array and convert it into an signed int then into a string. """
    return str(int.from_bytes(value, byteorder='little', signed=True))


def b2ih(value):
    """ Conversion of byte arrays into integers, Divide int by 100 to give two decimal places for weights"""
    return str(int(b2is(value)) / 100)


def hex_byte(value):
    """ Convert to byte / two digit hex """
    return f"{int(value):02x}"

def get_enabled_custom_modes(custom_mode: int) -> list[str]:
    """ Get a list of enabled custom modes from the Pet Door custom mode bitmask. """
    return [mode.name for mode in PetDoorCustomMode if mode.value & custom_mode]

# Main Parsing Functions
def parse_hub_frame(pethubrecord, offset, length):
    """ Parse Hub Frames aka 132 messages sent to the hub """
    frame_response = Box()
    registers = bytearray.fromhex(pethubrecord['Hub']['Registers'])
    message_range = range(offset, offset + length)
    update_item = [pethubrecord['Hub']['Serial_Number']+"_Hub"]
    update_state = False
    new_device = False  # Is this a new device?

    if all(x in message_range for x in [3, 5]):  # Firmware Version
        frame_response.Firmware = str(int(registers[3])) + '.' + str(int(registers[5]))
        pethubrecord['Hub']['Device']['Firmware'] = str(int(registers[3])) + "." + str(int(registers[5]))
        update_state = True
    if all(x in message_range for x in [7]):  # Hardware Version
        frame_response.Hardware = str(int(registers[7]))
        pethubrecord['Hub']['Device']['Hardware'] = str(int(registers[7]))
        update_state = True
    if all(x in message_range for x in [15]):  # Adoption Mode
        frame_response.Adopt = HubAdoption(int(registers[15])).name
        update_state = True
    if all(x in message_range for x in [18]):  # LED Mode
        frame_response.LED = HubLeds(int(registers[18])).name
    if all(x in message_range for x in [34]):  # Total Up Time
        frame_response.Uptime = b2iu(registers[31:35])
        update_state = True
    if offset >= 45:
        """
        Device Info
         There are a max of 10 devices supported 0-9, starting at offset 45 and going for 16 bytes.
         First 8 bytes are the device MAC
         Byte 9 bitwise valid, status and product
         Next 3 bytes is RSSI info
         Next Remaining 4 is last heard
        """
        device_offsets = [45, 61, 77, 93, 109, 125, 141, 157, 173, 189]
        device_offset_number_start = bisect(device_offsets, offset)
        device_offset_number_end = bisect(device_offsets, offset + length)
        device_index = device_offset_number_start - 1
        log.debug(f"Hub Message - Device Status Update - Device %s", str(device_index))
        device_offset_start = 29 + (device_offset_number_start * 16)
        frame_response.Device_Index = device_index

        # If length is 8 and over device boundary then hub is booting and the complete message is received
        # Otherwise if length is under 8 it's a status update, so we already have the rest of the state.
        if (device_offset_number_start != device_offset_number_end and length == 8) \
                or (length < 8 and ((device_offset_start + 7) < offset)):
            mac_address = registers[device_offset_start:device_offset_start + 8].hex().upper()
            status = registers[device_offset_start + 8]
            RSSIHex = registers[device_offset_start + 9:device_offset_start + 12].hex()
            lastheard = b2is(registers[device_offset_start + 12:device_offset_start + 16])
            frame_response.MsgType = "DeviceStatus"
            if status >> 0 & 1 == 1:  # Valid device
                update_state = True
                frame_response.Mac_Address = mac_address
                frame_response.Valid = status >> 0 & 1
                frame_response.Online = status >> 1 & 1
                frame_response.Product_Id = status >> 2
                frame_response.RSSIHex = RSSIHex
                frame_response.LastHeard = lastheard
                if (mac_address != '0000000000000000') and (mac_address not in pethubrecord):
                    # New Device, so adding to config
                    log.info('New Device - Mac: %s Product_Id %s', mac_address, frame_response.Product_Id)
                    new_device = {
                        mac_address: {
                            'Name': mac_address,
                            'Product_Id': frame_response.Product_Id,
                            'Serial_Number': '',
                            'Mac_Address': mac_address,
                            'Index': device_index,
                            'State': 'Online' if frame_response.Online == 1 else 'Offline',
                            'RSSIHex': RSSIHex,
                            'LastHeard': lastheard,
                            'New_Device': True
                        }
                    }
                    pethubrecord.merge_update(new_device)
                elif mac_address in pethubrecord:  # Status update
                    pethubrecord[mac_address]['State'] = 'Online' if frame_response.Online == 1 else 'Offline'
                    pethubrecord[mac_address]['Last_Heard'] = lastheard
                    update_item.append(pethubrecord['Hub']['Serial_Number']+'_'+mac_address)
            else:
                frame_response.Valid = 0

    frame_response.Operation = "Hub"
    frame_response.Update_State = update_state
    frame_response.Update_Item = update_item
    frame_response.New_Device = new_device
    return [frame_response]


def parse_frame(pethubrecord, time_zone, hub, value):
    """
     Parse Sub-frame from Feeder, Cat Flap or Poseidon
     Single frame payload to be parsed, can be called by 126 Multi status frame or 127 Single command frame
    """
    frame_response = Box()
    update_state = False
    # log.debug('MSG: Frame PetHubRecord %s', pethubrecord)
    update_item = [hub+'_'+pethubrecord[MAC]]
    New_Tag = False

    # Frame timestamp value
    frame_response.frametimestamp = devicetimestamp(value[4:8], time_zone, '')

    if DEBUGRESPONSE:
        frame_response.Message = value.hex()

    # Return the message type and counter which is two bytes as they are needed for acknowledgement of the message back
    frame_response.data = Box({'msg': hex_byte(value[0]), 'counter': b2iu(value[2:4])})

    if value[0] in [0x16, 0x17]:  # **TODO Unknown messages
        op = hex_byte(value[0])
        frame_response.Operation = "Msg" + op
        frame_response.Message = value[8:].hex()

    elif value[0] == 0x00:  # Command - Acknowledge message
        frame_response.Operation = "Ack"
        frame_response.Message = hex_byte(value[8])

    elif value[0] == 0x01:  # Command - Query Data
        frame_response.Operation = "Query"
        frame_response.Type = hex_byte(value[8])
        frame_response.SubData = value[9:].hex()

    elif value[0] == 0x07:  # Command - Set Time
        frame_response.Operation = "Time"
        frame_response.Type = value[8:].hex()
        log.debug("Device: Time:%s ", frame_response.Type)

    elif value[0] == 0x09:  # Command - Update subtypes depending on device type
        frame_response.Operation = "UpdateState"
        update_state = True
        print('O9 ',value[9:12])
        submessagevalue = b2is(value[9:12])
        print('Value ', submessagevalue, value[8])
        if value[8] == 0x05:  # Training mode
            frame_response.SubOperation = "Training"
            frame_response.Mode = submessagevalue
            pethubrecord['Training_Mode'] = submessagevalue
        elif value[8] == 0x0a:  # Set Bowl1 Weight
            frame_response.SubOperation = "SetBowl1Target"
            weight = str(round(int(submessagevalue) / 100))
            frame_response.Weight = weight
            if 'Bowl_Target' in pethubrecord and int(weight) > 0:
                pethubrecord['Bowl_Target'][0] = weight
        elif value[8] == 0x0b:  # Set Bowl2 Weight
            frame_response.SubOperation = "SetBowl2Target"
            weight = str(round(int(submessagevalue) / 100))
            frame_response.Weight = weight
            if 'Bowl_Target' in pethubrecord and int(weight) > 0:
                pethubrecord['Bowl_Target'][1] = weight
        elif value[8] == 0x0c:  # Set Bowl Count either 1 or 2
            frame_response.SubOperation = "SetBowlCount"
            bowls = FeederBowls(int(submessagevalue)).name.title()
            frame_response.Bowls = bowls
            if 'Bowl_Count' in pethubrecord and int(submessagevalue) > 0:
                pethubrecord['Bowl_Count'] = bowls
        elif value[8] == 0x0d:  # Set Feeder Close Delay
            frame_response.SubOperation = "SetCloseDelay"
            delay = FeederCloseDelay(int(submessagevalue)).name.title()
            frame_response.Delay = delay
            if 'Close_Delay' in pethubrecord and int(submessagevalue) > 0:
                pethubrecord['Close_Delay'] = int(submessagevalue)
        elif value[8] == 0x0f:  # Poseidon Add Tag/Pet - Command message selecting "add pet" from the cloud
            frame_response.SubOperation = "AddTag"
            frame_response.State = int(submessagevalue)
        elif value[8] == 0x12:  # **TODO - Always seems to be the same value, either 500, or 5000
            frame_response.SubOperation = "Set12"
            frame_response.Value = submessagevalue
            frame_response.Message = value[9:].hex()
        elif value[8] == 0x14:  # Custom Modes for Feeder
            frame_response.SubOperation = "Custom-" + FeederCustomMode(int(submessagevalue)).name.title()
            frame_response.CustomMode = submessagevalue
            frame_response.Message = FeederCustomMode(int(submessagevalue)).name.title()
            if 'Custom_Mode' in pethubrecord and int(submessagevalue) > 0:
                pethubrecord['Custom_Mode'] = submessagevalue
        elif value[8] == 0x17:  # Set ZeroBowl1Weight
            frame_response.SubOperation = "ZeroBowl1"
            frame_response.Weight = submessagevalue
        elif value[8] == 0x18:  # Set ZeroBowl2Weight
            frame_response.SubOperation = "ZeroBowl2"
            frame_response.Weight = submessagevalue
        elif value[8] == 0x19:  # SetTODO 19
            frame_response.SubOperation = "SetTODO"
            frame_response.Message = value[9:].hex()
        else:
            frame_response.SubOperation = "SetTODO" + str(value[8])
            frame_response.Message = value[9:].hex()
        log.debug("Device: Update State 09:%s %s", frame_response.SubOperation, str(submessagevalue))

    elif value[0] == 0x0b:  # Status - Boot Device Information
        frame_response.Operation = "DeviceInfo"
        frame_response.Hardware = b2is(value[8:12])
        frame_response.Firmware = b2is(value[12:16])
        frame_response.EntityType = EntityType(value[64]).name
        frame_response.Val1 = b2is(value[16:20])        # **TODO Some value
        frame_response.HexTS = value[20:28].hex()
        frame_response.SerialHex = value[36:45].hex()  # **TODO Serial Number calc somehow
        version = Box({
            "Device": {
                "Hardware": frame_response.Hardware,
                "Firmware": frame_response.Firmware
            }
        })
        log.debug("Device: Boot 0B:%s", frame_response.EntityType)
        pethubrecord.merge_update(version)

    elif value[0] == 0x0c:  # Status - Battery state for four bytes
        frame_response.Operation = 'Battery'
        battery = str(round(int(b2is(value[8:12])) / 1000, 4))
        frame_response.Battery = battery
        frame_response.Value2 = str(int(b2is(value[12:16])))  # **TODO Not sure what this value is.
        frame_response.Value3 = str(int(b2is(value[16:20])))  # **TODO Or this one
        frame_response.BatteryTime = devicetimestamp(value[20:24], time_zone, '')  # **TODO Last time the time was set?
        pethubrecord['Battery'] = battery
        log.debug("Device: Battery:%s", battery)
        update_state = True

    elif value[0] == 0x0d:  # Status - Lock state of Cat Flap and zeroing scales
        if len(value) == 20:  # Zeroing Scales
            frame_response.Operation = 'ZeroScales'
            frame_response.Scale = FeederZeroScales(int(value[19])).name.title()
            log.debug("Device: ZeroScales:%s", frame_response.Scale)
        else:
            frame_response.Operation = 'CurfewLockState'
            frame_response.LockState = CatFlapLockState(int(value[29])).name.title()
            lock_state = LockState[frame_response.LockState.upper()].value
            pethubrecord['Curfew_Enabled'] = True if lock_state else False
            frame_response.LockStateNumber = str(lock_state)
            log.debug('CatFlap: CurfewLockState %s', str(lock_state))
            update_state = True

    elif value[0] == 0x10:  # **TODO Some Boot Message
        frame_response.Operation = "BootMsg"
        frame_response.Val1 = b2iu(value[8:12])
        frame_response.Val2 = b2iu(value[12:16])
        frame_response.Val3 = b2iu(value[16:20])
        frame_response.Val4 = b2iu(value[20:24])
        frame_response.Message = value[8:].hex()
        log.debug("Device: Bootmsg:%s", frame_response.Message)

    elif value[0] == 0x11:  # Command - Provision tag to device and set lock states on cat flap.
        frame_response.TagOffset = str(value[16])
        frame_response.LockState = CatFlapLockState(int(value[15])).name.title()
        if value[16] == 0x00:  # CatFlap Status Update on offset 0 for locking
            frame_response.Operation = "LockState"
            # frame_response.Tag = "Empty"
            pethubrecord['Locking_Mode'] = LockState[frame_response.LockState.upper()].value
            print('Lock State ',pethubrecord['Locking_Mode'])
            frame_response.LockStateNumber = str(pethubrecord['Locking_Mode'])
            update_state = True
        elif value[14] in [0x01, 0x03, 0x07]:  # Provisioning HDX (1) or FDX-B (3) chip
            frame_response.Operation = "Tag"
            frame_response.LockStateNumber = str(int(value[15]))
            frame_response.TagState = TagState(value[17]).name.title()
            tag = hex_to_tag(value[8:15])
            frame_response.Tag = [tag]
            if tag != 'Empty':
                # print(pethubrecord)
                if frame_response.TagOffset in pethubrecord['Tags']:
                    if not pethubrecord['Tags'][frame_response.TagOffset]['Tag'] == tag:
                        pethubrecord['Tags'][frame_response.TagOffset] = {"Tag": tag}
                        update_state = True
                else:
                    pethubrecord['Tags'][frame_response.TagOffset] = {"Tag": tag}
                    update_state = True
                    New_Tag = True
        else:
            frame_response.Operation = "Unknown-11"
            frame_response.Message = value.hex()
        log.debug("Device: Provision Tag:%s Offset:%s", frame_response.LockState, frame_response.TagOffset)

    elif value[0] == 0x12:  # Command - Curfew of Cat Flap
        """
          Seems like setting the curfew you can send a command message and you get an ack, but for whatever reason
          This is one of the few settings that doesn't report back once it has been set so is only a command message
          Responds with an ack and that's it.
        """
        frame_response.Operation = 'Curfew'
        frame_response.Curfew = []
        curfews = ""
        pethubrecord['Curfew_Enabled'] = False
        for curfew_offset in range(16, 44, 9):
            curfew_entry = value[curfew_offset:curfew_offset+9]
            if CatFlapCurfewState(curfew_entry[8]).name == 'ON':
                pethubrecord['Curfew_Enabled'] = True
                start = devicetimestamp(curfew_entry[0:4], 'UTC', "%H:%M")
                end = devicetimestamp(curfew_entry[4:8], 'UTC', "%H:%M")
                if len(curfews) > 1:
                    curfews = curfews + ","
                curfews = curfews + start + "-" + end
                log.debug('MSG: Curfew Start %s End %s Entry %s', start, end, curfew_entry.hex())
                frame_response.Curfew.append(Box({'State': curfew_entry[8],
                                             'StartTime': devicetimestamp(curfew_entry[0:4], time_zone, ''),
                                             'EndTime': devicetimestamp(curfew_entry[4:8], time_zone, ''),
                                             'Start': start,
                                             'End': end}))
        frame_response.Curfews = curfews
        pethubrecord['Curfews'] = curfews
        log.debug('MSG: Curfews %s', curfews)
        update_state = True
        log.debug("Device: Curfew Curfews:%s", curfews)

    elif value[0] == 0x13:  # Status - Pet Movement through Cat Flap
        frame_response.Tag = [hex_to_tag(value[18:25])]
        animaldirection = (value[16] << 8) + value[17]
        if CatFlapDirection.has_value(animaldirection):
            frame_response.Direction = CatFlapDirection(animaldirection).name.title()
        else:
            frame_response.Direction = '**UNKNOWN**'
        frame_response.Operation = 'PetMovement'
        frame_response.NumberValue = b2iu(value[12:16])
        frame_response.OtherTS = b2iu(value[25:29])
        log.debug("Device: PetMovement Direction:%s Tag:%s ", frame_response.Direction, frame_response.Tag)
        update_item.append(frame_response.Tag[0])
        update_state = True

    elif value[0] == 0x18:  # Status - Feeder Feeding
        frame_response.Operation = 'Feed'
        if FeederState.has_value(value[15]):
            frame_response.Action = FeederState(int(value[15])).name.title()  # Action
            pethubrecord['Lid_State'] = frame_response.Action
            frame_response.Time = b2iu(value[16:17])                  # Open Seconds
            frame_response.Bowl1From = b2ih(value[19:23])             # Or if single bowl only this value is set
            frame_response.Bowl1To = b2ih(value[23:27])
            frame_response.Bowl1Delta = str(round(float(frame_response.Bowl1To) - float(frame_response.Bowl1From), 2))
            frame_response.Bowl2From = b2ih(value[27:31])
            frame_response.Bowl2To = b2ih(value[31:35])
            frame_response.Bowl2Delta = str(round(float(frame_response.Bowl2To) - float(frame_response.Bowl2From), 2))
            pethubrecord['Time_Open'] = frame_response.Time
            if frame_response.Action.endswith('Closed'):
                pethubrecord['Bowl_Weight'] = [frame_response.Bowl1To]
            else:
                pethubrecord['Bowl_Weight'] = [frame_response.Bowl1From]
            delta = [frame_response.Bowl1Delta]
            if pethubrecord['Bowl_Count'] == 2:
                if frame_response.Action.endswith('Closed'):
                    pethubrecord['Bowl_Weight'].append(frame_response.Bowl2To)
                else:
                    pethubrecord['Bowl_Weight'].append(frame_response.Bowl2From)
                delta.append(frame_response.Bowl2Delta)
            pethubrecord['Bowl_Delta'] = delta
            frame_response.Delta = delta
            # If a 0-3 it's a tag otherwise 4-8 is manual
            if frame_response.Action.endswith('Closed') and value[15] in range(0, 3):
                frame_response.Tag = [hex_to_tag(value[8:15])]
            update_state = True
            log.debug("Device: Feeder State:%s Time:%s To Weight1:%s To Weight2:%s", frame_response.Action,
                      str(frame_response.Time), str(frame_response.Bowl1To), str(frame_response.Bowl2To))
        else:
            frame_response.Operation = 'Unknown'
            frame_response.Message = value.hex()
            log.debug("Device: Feeder Unknown %s", value.hex())

    elif value[0] == 0x1B:  # Status Poseidon Drinking frame, similar to a feeder frame
        frame_response.Operation = "Drinking"
        frame_response.Action = PoseidonState(value[8]).name.title()  # Action performed
        frame_response.Time = b2iu(value[9:11])   # Time spent
        frame_response.From = b2ih(value[12:16])  # Weight From
        frame_response.To = b2ih(value[16:20])    # Weight To
        frame_response.Delta = str(round(float(frame_response.To) - float(frame_response.From), 2))
        frame_response.Counter = hex_byte(value[20])    # Counter
        # frame_response.Message = value.hex()
        frame_response.TagCount = value[26]
        if frame_response.TagCount > 0:
            frame_response.Tag = []
            # frame_response.Animal = []
            for i in range(27, len(value), 7):
                tag = hex_to_tag(value[i:i + 7])
                frame_response.Tag.append(tag)
        pethubrecord['Time'] = frame_response.Time
        pethubrecord['Bowl_Weight'] = [frame_response.To]
        pethubrecord['Bowl_Delta'] = [frame_response.Delta]
        frame_response.Delta = [frame_response.Delta]
        update_state = True
        log.debug("Device: Drinking Time:%s Weight:%s", str(frame_response.Time), str(frame_response.To))

    else:
        log.debug("Device: Unknown %s", str(value.hex()))
        frame_response.Operation = "Unknown"
        frame_response.Message = value.hex()
    frame_response.Update_State = update_state
    frame_response.Update_Item = update_item
    frame_response.New_Tag = New_Tag
    return frame_response


def parse_multi_frame(pethubrecord, time_zone, hub, payload):
    """
     Parse Multi-Frame from Feeder, CatFlap or Poseidon
     126 Frames aka can have multiple messages, so need to loop until you get to the end of the frame
    """
    multi_response = []
    while len(payload) > 2:
        sub_frame_length = payload[0] + 1
        currentframe = payload[1:sub_frame_length]
        frame_response = parse_frame(pethubrecord, time_zone, hub, currentframe)
        multi_response.append(frame_response)
        # Remove the parsed payload and loop again
        del payload[0:sub_frame_length]
    # log.debug('MSG: Multi Frame Response %s', json.dumps(multi_response))
    return multi_response


def parse132frame(offset, value):
    """
     Non Pet Door devices sends a 132 Status messages, but they only have a 33 type for the time and battery
     I think these 132 frames are calculated by the Hub as part of the RSSI frame.
    """
    frame_response = Box()
    message = bytearray.fromhex(value)
    if offset == 33:  # Battery and Door Time
        frame_response.Operation = "Data132Battery"
        # Battery ADC Calculation, Battery full 0xbd, and dies at 0x61/0x5f.
        # ADC Start for Pet Door, not sure if this is consistent or just my door
        adcstart = 2.1075
        # ADC Step value for each increment of the adc value
        adcstep = 0.0225
        battadc = round((int(message[1]) * adcstep) + adcstart, 4)
        frame_response.Battery = str(battadc)
        frame_response.Time = converttime(message[2:4])
    else:
        frame_response.Operation = "Other"
        frame_response.Message = value
    return [frame_response]


def parse_door_frame(pethubrecord, hub, device_item, offset, length):
    """ Parse Pet Door Frames aka 132's sent by only the pet door """
    operation = []
    update_state = False
    update_item = [hub+'_'+device_item]
    New_Tag = False
    frame_response = Box()
    registers = bytearray.fromhex(pethubrecord['Registers'])
    message_range = range(offset, offset + length)
    # print(registers[])
    if all(x in message_range for x in [33]):  # Battery and Door Time
        log.debug("PETDOOR: Register 33 - Battery %s", str(message_range))
        operation.append("Battery")
        # Battery ADC Calculation, Battery full 0xbd, and dies at 0x61/0x5f.
        # ADC Start for Pet Door, not sure if this is consistent or just my door
        adcstart = 2.1075
        # ADC Step value for each increment of the adc value
        adcstep = 0.0225
        frame_response.Battery = str(round((int(registers[33]) * adcstep) + adcstart, 4))
        frame_response.BatteryADC = str(int(registers[33]))
        pethubrecord['Battery'] = frame_response.Battery
        pethubrecord['BatteryADC'] = frame_response.BatteryADC
        update_state = True
    if all(x in message_range for x in [34, 35]):  # Set local time for Pet Door 34 = HH in hex and 35 = MM
        log.debug("PETDOOR: Register 34 - Time %s", str(message_range))
        operation.append("Time")
        frame_response.Time = converttime(registers[34:34+2])
        timearray = registers[34:34+2]
        if timearray[1] >= 128:
            timearray[1] -= 128
        frame_response.TimeMins = str((timearray[0] * 60) + timearray[1])
    if all(x in message_range for x in [36]):  # Lock state
        log.debug("PETDOOR: Register 36 - Lockstate %s", str(message_range))
        operation.append("LockState")
        frame_response.LockStateNumber = registers[36]
        frame_response.LockState = PetDoorLockState(int(frame_response.LockStateNumber)).name.title()
        pethubrecord['Locking_Mode'] = frame_response.LockStateNumber
        update_state = True
    if all(x in message_range for x in [40]):  # Keep pets out to allow pets to come in state
        log.debug("PETDOOR: Register 40 - LockedOutState %s", str(message_range))
        operation.append("LockedOutState")
        frame_response.LockedOut = PetDoorLockedOutState(int(registers[40])).name.title()
        pethubrecord['Locked_Out_State'] = frame_response.LockedOut
    if all(x in message_range for x in [59]):  # Provisioned Tag Count
        log.debug("PETDOOR: Register 59 - Tag Count %s", str(message_range))
        operation.append("TagCount")
        frame_response.TagCount = registers[59]
        pethubrecord['Tag_Count'] = registers[59]
    if all(x in message_range for x in [60]):  # Next free tag slot
        log.debug("PETDOOR: Register 60 - next chip %s", str(message_range))
        operation.append("ProvFreeSlot")
        frame_response.ChipSlot = registers[60]
    if all(x in message_range for x in [63]):  # Custom Mode
        log.debug("PETDOOR: Register 61-63 - Custom Mode %s", str(message_range))
        operation.append("CustomMode")
        custom_mode = int.from_bytes(registers[61:64], byteorder='big')
        enabled_modes = get_enabled_custom_modes(custom_mode)
        log.debug("Enabled Custom Modes: %s", enabled_modes)
        frame_response.CustomMode = str(custom_mode)    # Store the raw custom mode value as an int
        frame_response.CustomModes = enabled_modes      # Store the enabled custom modes as a list of human readable strings
        pethubrecord['Custom_Mode'] = str(custom_mode)
        pethubrecord['Custom_Modes'] = str(enabled_modes)
        update_state = True
    if offset in range(91, 309):  # Provisioned tags
        log.debug("PETDOOR: Register 91-309 - Provisioned Tags %s", str(message_range))
        operation.append("Tag")
        frame_response.TagOffset = str(round((int(offset) - 84) / 7) -1)  # Calculate the tag offset number (0 indexed. This wasn't originally the case, but it matches what's on line 634)
        tag = door_hex_to_tag(registers[offset:offset+7])                 # Calculate tag Number
        frame_response.Tag = [tag]
        if tag != 'Empty':
            log.info("Found tag in door message with value of %s at offset %s", tag, frame_response.TagOffset)
            if frame_response.TagOffset in pethubrecord['Tags']:
                log.info("Matches existing offset")
                if not pethubrecord['Tags'][frame_response.TagOffset]['Tag'] == tag:
                    log.info("Updating tag %s at offset %s", tag, frame_response.TagOffset)
                    pethubrecord['Tags'][frame_response.TagOffset] = {"Tag": tag}
                    update_state = True
            else:
                log.info("Adding new tag %s at offset %s", tag, frame_response.TagOffset)
                pethubrecord['Tags'][frame_response.TagOffset] = {"Tag": tag}
                update_state = True
                New_Tag = True
    if offset == 519:  # Curfew
        log.debug("PETDOOR: Register 519 - curfew %s", str(message_range))
        operation.append("Curfew")
        frame_response.CurfewState = CurfewState(registers[519]).name.title()
        frame_response.CurfewStateNumber = registers[519]
        frame_response.Curfews = str(registers[520]).zfill(2) + ":" + str(registers[521]).zfill(2) + '-' + str(registers[522]).zfill(2) + ":" + str(registers[523]).zfill(2)
        pethubrecord['Curfews'] = frame_response.Curfews
    if offset in range(525, 618):  # Pet movement state in or out
        log.debug("PETDOOR: Register 525-618 offset %s - curfew %s", offset, str(message_range))
        operation.append("PetMovementRegister")
        frame_response.TagOffset = str(int(round((int(offset) - 522) / 3) - 1))  # Calculate the tag offset number
        frame_response.Time = converttime(registers[offset:offset+2])
        frame_response.PetDoorDirectionID = registers[offset+2]
        if frame_response.PetDoorDirectionID > 0:
            if PetDoorDirection.has_value(frame_response.PetDoorDirectionID):
                frame_response.Direction = PetDoorDirection(frame_response.PetDoorDirectionID).name
            else:
                frame_response.Direction = hex_byte(frame_response.PetDoorDirectionID)
        else:
            frame_response.Direction = "Null"
        if TAGLOOKUP:
            if frame_response.TagOffset in pethubrecord['Tags']:
                Tag = pethubrecord['Tags'][frame_response.TagOffset]['Tag']
                frame_response.Tag = [Tag]
                update_item.append(Tag)
                update_state = True

    if offset == 621:  # Unknown pet went outside, should probably do a lookup to see what animals are still inside and update who is left??
        log.debug("PETDOOR: Register 621 Unknown pet went outside offset %s - %s", offset, str(message_range))
        # frame_response.Operation = op
        operation.append("PetMovement")
        # frame_response.PetOffset="621"
        frame_response.PetOffset = 32
        # frame_response.Tag = ['Unknown']
        frame_response.Direction = "Outside"
        # frame_response.State="OFF"

    frame_response.Operation = operation
    frame_response.Update_State = update_state
    frame_response.Update_Item = update_item
    frame_response.New_Tag = New_Tag
    return [frame_response]


def parse_door_movement(pethubrecord, value):
    """ Pet Door Movement Frame """
    update_state = False
    Update_Item = ['']
    message = bytearray.fromhex(value)
    msg_op = "PetMovement"
    frame_response = Box()
    frame_response.Message = value
    frame_response.Operation = msg_op
    frame_response.TagOffset = str(message[0])  # Pet Offset
    frame_response.Time = converttime(message[1:3])  # Timestamp in local time
    frame_response.Counter = message[10]  # Timestamp in local time
    petdirection = message[3]  # Direction
    if petdirection > 0 and int(frame_response.TagOffset) < 0x20:
        if PetDoorDirection.has_value(petdirection):
            frame_response.Direction = PetDoorDirection(petdirection).name
        else:
            frame_response.Direction = "Other " + hex_byte(petdirection)
    else:
        frame_response.Direction = "Outside"
    if TAGLOOKUP:
        if frame_response.TagOffset in pethubrecord['Tags']:
            tag = pethubrecord['Tags'][frame_response.TagOffset]['Tag']
            frame_response.Tag = [tag]
            Update_Item = [tag]
            update_state = True

    frame_response.Update_State = update_state
    frame_response.Update_Item = Update_Item
    return [frame_response]


def parse_hub(pethubconfig, topic, message):
    """ Parse main hub message """
    response = Box()
    msgsplit = message.split()
    topicsplit = topic.split('/')
    topic_offset = 2  # Offset where Hub Serial Number is
    hub = topicsplit[topic_offset]
    devices = pethubconfig[DEV]
    Save_Config = False
    # Try and convert first field if it is a timestamp,
    # or generate a timestamp based off current time if hub offline.
    try:
        int(msgsplit[0], 16)
        response.timestamp = str(datetime.utcfromtimestamp(int(msgsplit[0], 16)))
    except ValueError:
        response.timestamp = str(datetime.utcnow().replace(microsecond=0))

    time_zone = pethubconfig['Config']['Timezone']

    # Determine device product_id aka device type
    if topic.endswith('/messages'):
        # Hub, including the whole device and sub-device, so I can add if needed during hub boot.
        pethubdevices = devices[hub] if hub in devices else exit(1)
        # **TODO Add logic to dynamically create the hub if missing
        product_id = 1
        # device_item = hub + "_Hub"
        device_item = "Hub"
    else:
        # Any device not a hub
        mac = topicsplit[topic_offset + 2]
        pethubdevice = devices[hub][mac]
        # **TODO Add logic to dynamically create the device if missing
        product_id = pethubdevice['Product_Id']
        # device_item = hub + "_" + device
        device_item = mac

    # Determine operation
    if msgsplit[1] == "1000":
        response.Operation = "Command"
    else:
        response.Operation = "Status"

    log.info('MSG: %s from Hub %s Device %s Type %s', response.Operation, hub, device_item, EntityType(product_id).name)

    messageoffset = None
    messagelength = None

    # Update register array if it is a hub or a pet door as the 132
    if msgsplit[2] == '132' and product_id in [1, 3]:

        Save_Config = True
        # Message 132 has a counter at offset 3, Message 2 doesn't have the counter
        messageoffset = int(msgsplit[4])
        messagelength = int(msgsplit[5])
        # print(f"Hub Message at 132 offset={messageoffset} length={messagelength}")
        if product_id == 1:
            registers = bytearray.fromhex(pethubdevices['Hub']['Registers'])
        else:
            registers = bytearray.fromhex(pethubdevice['Registers'])
        registers[messageoffset:messageoffset + messagelength] = bytearray.fromhex("".join(msgsplit[6:]))
        if product_id == 1:
            pethubdevices['Hub']['Registers'] = registers.hex()
        else:
            pethubdevice['Registers'] = registers.hex()


    resp = []
    frame_response = Box()
    # Device message
    if msgsplit[0] == "Hub":  # Hub Offline Last Will message
        op = "HubState"
        frame_response.Operation = op
        frame_response.Message = message
        frame_response[op] = 'Offline'
        frame_response.Update_State = True
        # frame_response.Update_Item = [hub+"_Hub"]
        frame_response.Update_Item = [hub+"_Hub"]
        frame_response.Web_State = {topicsplit[1]+'_'+pethubdevices['Hub'][MAC]+'_state': 'Offline'}
        devices[topicsplit[topic_offset]]['Hub']['State'] = 'Offline'
        response.message = [frame_response]
    elif msgsplit[2] == "Hub":  # Hub online message
        op = "HubState"
        frame_response.Operation = op
        frame_response.Message = message
        frame_response[op] = 'Online'
        frame_response.Update_State = True
        # frame_response.Update_Item = [hub+"_Hub"]
        frame_response.Update_Item = [hub+"_Hub"]
        frame_response.Web_State = {topicsplit[1]+'_'+pethubdevices['Hub'][MAC]+'_state': 'Online'}
        devices[topicsplit[topic_offset]]['Hub']['State'] = 'Online'
        response.message = [frame_response]
    elif msgsplit[2] == "2":  # Command - Set Register to Hub or Pet Door
        registers = bytearray.fromhex('00' * 205 if product_id == 1 else '00' * 605)
        messageoffset = int(msgsplit[3])
        messagelength = int(msgsplit[4])
        registers[messageoffset:messageoffset + messagelength] = bytearray.fromhex("".join(msgsplit[5:]))
        messagetwo = {'Registers': registers.hex()}


        response.message = {"Command": "Set Register",
                            "Hub": hub,
                            "Device": device_item,
                            "Offset": str(int(msgsplit[4])),
                            "Length": str(int(msgsplit[5])),
                            "Payload": "".join(msgsplit[5:])}
    elif msgsplit[2] == "3":  # Command - Query Register
        response.message = {"Command": "Query Register",
                            "Hub": hub,
                            "Device": device_item,
                            "Offset": str(int(msgsplit[4])),
                            "Length": str(int(msgsplit[5])),
                            "Payload": "".join(msgsplit[5:])}

        response.message = {"Msg": "Dump to " + msgsplit[4], "Operation": ["Dump"]}
    elif msgsplit[2] == "8":  # Pet Movement through Pet Door
        response.message = parse_door_movement(pethubdevice, "".join(msgsplit[3:]))
    elif msgsplit[2] == "10":  # Hub Uptime
        op = "Uptime"
        uptime = str(int(msgsplit[3]))
        frame_response.Operation = op
        frame_response[op] = uptime
        frame_response.TS = msgsplit[4] + "-" + ':'.join(format(int(x), '02d') for x in msgsplit[5:8])
        frame_response.Reconnects = msgsplit[9]
        pethubdevices['Hub']['Uptime'] = uptime
        pethubdevices['Hub']['Reconnects'] = frame_response.Reconnects
        frame_response.Update_State = True
        frame_response.Update_Item = [hub+"_Hub"]
        response.message = [frame_response]
        # update_pethubconfig_status(pethubconfig)
    elif msgsplit[2] == "126":  # 126 Feeder/CatDoor/Poseidon multi-frame status message
        multi_frame = bytearray.fromhex("".join(msgsplit[3:]))
        response.message = parse_multi_frame(pethubdevice, time_zone, hub, multi_frame)
        for message in response.message:
            if message.Operation not in ['Ack', 'Data132Battery'] and not isinstance(message.Operation, list):
                ackmsg = generatemessage(pethubconfig, hub, product_id, 'Ack', mac=mac, suboperation=message.data.msg)
                if 'error' not in ackmsg:
                    response.merge_update({'HubMessage': [ackmsg]})
    elif msgsplit[2] == "127":  # 127 Feeder/CatDoor/Poseidon frame sent/control message
        single_frame = bytearray.fromhex("".join(msgsplit[3:]))
        response.message = [parse_frame(pethubdevice, time_zone, hub, single_frame)]
    elif msgsplit[2] == "132" and product_id == 1:  # Hub Frame
        response.message = parse_hub_frame(pethubdevices, messageoffset, messagelength)
    elif msgsplit[2] == "132" and product_id == 3:  # Pet Door Status or Action
        response.message = parse_door_frame(pethubdevice, hub, device_item, messageoffset, messagelength)
    elif msgsplit[2] == "132":  # Non-Pet Door 132 Status
        log.info('parse other')
        # Status message has a counter at offset 4 we can ignore:
        msgsplit[5] = hex_byte(msgsplit[5])  # Convert length at offset 5 which is decimal into hex byte so we pass it as a hex string to parsedataframe
        response.message = parse132frame(int(msgsplit[4]), "".join(msgsplit[5:]))
    else:
        resp.append({"Msg": message})
        resp.append({"Operation": ["ERROR"]})
        response.message = resp
    response.merge_update({"Save_Config": Save_Config})
    pethubconfig[DEV] = devices
    return Box(response)
