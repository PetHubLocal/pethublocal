# Test Pet Hub Local
import pytest
import json
import sys

sys.path.append('..')
import pethublocal.message as p
import pethublocal.generate as g
import pethublocal as log
from pethublocal.functions import config_load, config_save, json_print
from pethublocal.consts import CFG

pethubconfig = config_load()

# Variables to log to console or mqtt
TESTING_MESSAGE = True
TESTING_MQTT = False
hub = 'pethub/hub/'

if TESTING_MQTT and 'MQTTHost' in pethubconfig[CFG]:
    host = pethubconfig[CFG]['MQTTHost'] if 'MQTTHost' in pethubconfig[CFG] else '127.0.0.1'
    port = pethubconfig[CFG]['MQTTPort'] if 'MQTTPort' in pethubconfig[CFG] else 1883
    log.info('PyTest: Hub Init MQ %s', host)
    import paho.mqtt.client as mq
    mc = mq.Client("Pet-Hub-Test", clean_session=False)
    mc.connect(host, port)


def run_test(name, pethubconfig, topic, mqtt_message):
    log.info('TEST: ' + name)
    mqtt_topic = str(hub + topic)
    log.info('Topic: %s Message: %s', mqtt_topic, mqtt_message)
    result = {}
    if TESTING_MQTT:
        log.info('PyTest: Hub MQTT Publish')
        mqtt_result = mc.publish(mqtt_topic, mqtt_message, 1, False)
        log.info('Pytest: Publish ' + str(mqtt_result))

    if TESTING_MESSAGE:
        result = p.parse_hub(pethubconfig, mqtt_topic, mqtt_message)
        log.info(json_print(result))
        config_save(pethubconfig)
    return result


@pytest.fixture
def global_variables():
    pytest.hub = 'H010-0123456'
    pytest.mac = '3333333333333333'
    pytest.devtype = 3               # Device Type 3 = PetDoor


def setup_module():
    log.info('setup')


def teardown_module():
    log.info('teardown')
    with open('pethubconfig-updated.json', 'w') as fp:
        json.dump(pethubconfig, fp, indent=4)


@pytest.mark.parametrize("status,battery,batteryadc,time,timemins", [
    ('33 3 8c 16 32', '5.2575', '140', '22:50', '1370'),  # Unlocked
])
@pytest.mark.pethubcommand
def test_petdoor_status_batterytime(global_variables, request, status, battery, batteryadc, time, timemins):
    log.info('TEST: ' + request.node.name)
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0010 132 1 " + status)
    log.info(json_print(result))
    assert result.Operation == 'Status'
    assert result.message[0].Battery == battery
    assert result.message[0].BatteryADC == batteryadc
    assert result.message[0].Time == time
    assert result.message[0].TimeMins == timemins


#Pet Door Status
@pytest.mark.parametrize("test_query,LockState", [
    ("36 1 00", "Unlocked"), # Unlocked
    ("36 1 01", "Keepin"),   # Keep In
    ("36 1 02", "Keepout"),  # Keep Out
    ("36 1 03", "Locked"),   # Locked in and out
    ("36 1 04", "Curfew"),   # Curfew Mode
])
@pytest.mark.pethubcommand
def test_petdoor_status_lockstate(global_variables, request, test_query, LockState):  # Set Petdoor to modes
    log.info('TEST: ' + request.node.name)
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0010 132 1 " + test_query)
    log.info(json_print(result))
    assert result.Operation == 'Status'
    assert result.message[0].LockState == LockState
    # assert result.message[0].LockStateNumber == int(test_query)
#    assert 'LockState' in result.message[-1].Operation


#Pet Door Status
@pytest.mark.parametrize("test_query,LockState", [
    ("40 1 02", "Normal"),     # Keep Out Normal
    ("40 1 03", "Lockedout"),  # Keep Out Locked Out
])
@pytest.mark.pethubcommand
def test_petdoor_status_lockedoutstate(global_variables, request, test_query, LockState):  # Set Petdoor to modes
    log.info('TEST: ' + request.node.name)
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0010 132 1 " + test_query)
    log.info(json_print(result))
    assert result.Operation == 'Status'
    assert result.message[0].LockedOut == LockState


@pytest.mark.parametrize("status", [
    ("8 01 0a 32 40 00 ff 1a 44 02 1a 1a 01 02"),  # LookedIn
    ("132 173 528 3 0a 32 40"),                    # LookedIn
    ("8 02 16 36 62 00 16 a5 44 00 90 a5 01 03"),  # Outside
    ("132 146 531 3 16 36 62"),                    # Outside
    ("8 02 00 1d 61 00 3b a6 44 01 91 a6 01 e0"),  # Inside
    ("132 156 531 3 00 1d 61"),                    # Inside
    ("8 20 03 31 d0 88 9c 99 0a d2 00 a7 01 12"),  # Unknown Outside
    ("132 177 621 9 03 31 d0 88 9c 99 0a d2 00"),  # Unknown Outside
    ("132 153 40 1 02"),                           # Locked out Normal
])
@pytest.mark.pethubcommand
def test_petdoor_status_petmovement(global_variables, request, status):  # Set Petdoor to modes
    log.info('TEST: ' + request.node.name)
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0010 " + status)
    log.info(json_print(result))
    assert result.Operation == 'Status'


#Pet Door Commands
# @pytest.mark.parametrize("test_query,LockState", [
#     ("00", "Unlocked"),
#     ("01", "Keepin"),
#     ("02", "Keepout"),
#     ("03", "Locked"),
#     ("04", "Curfew"),
# ])
# @pytest.mark.pethubcommand
# def test_petdoor_command_lockstate(global_variables, request, test_query, LockState):  # Set Petdoor to modes
#     log.info('TEST: ' + request.node.name)
#     result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 1000 2 36 1 " + test_query)
#     log.info(json_print(result))
#     assert result.Operation == 'Command'
#     assert result.message[0].LockState == LockState
#     assert result.message[0].LockStateNumber == int(test_query)
#     assert 'LockState' in result.message[1].Operation
#
#
# @pytest.mark.parametrize("test_query, timefrom, timeto, curfewstate", [
#     ("00", "00 00", "00 00", "Disabled"),
#     ("01", "01 00", "02 00", "Off"),
#     ("02", "01 00", "02 00", "On"),
#     ("03", "00 00", "00 00", "Status"),
# ])
# @pytest.mark.pethubcommand
# def test_petdoor_command_curfew(global_variables, request, test_query, timefrom, timeto, curfewstate):  # Set Petdoor to modes
#     log.info('TEST: ' + request.node.name)
#     result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 1000 2 519 6 " + test_query + " " + timefrom + " " + timeto + " 00")
#     log.info(json_print(result))
#     assert result.Operation == 'Command'
#     assert result.message[0].CurfewState == curfewstate
#     assert result.message[0].CurfewStateNumber == int(test_query)
#     assert result.message[0].Curfews == timefrom.replace(" ", ":")+'-'+timeto.replace(" ", ":")
#     assert 'Curfew' in result.message[1].Operation
#
#
# @pytest.mark.parametrize("test_query, resultvalue, resultmsg", [
#     ("00 00 00",  "0", ["DISABLED"]),
#     ("00 00 01",  "1", ["NONSELECTIVE"]),
#     ("00 00 02",  "2", ["RECHARGEABLES"]),
#     ("00 00 03",  "3", ["NONSELECTIVE", "RECHARGEABLES"]),
#     ("00 00 04",  "4", ["THREESECONDS"]),
#     ("00 00 05",  "5", ["NONSELECTIVE", "THREESECONDS"]),
#     ("00 00 08",  "8", ["TENSECONDS"]),
#     ("00 00 10", "16", ["INTRUDER"]),
#     ("00 00 20", "32", ["OPPOSITECURFEW"]),
# ])
# @pytest.mark.pethubcommand
# def test_petdoor_command_custom(global_variables, request, test_query, resultvalue, resultmsg):  # Set Petdoor to modes
#     log.info('TEST: ' + request.node.name)
#     result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 1000 2 61 3 " + test_query)
#     log.info(json_print(result))
#     assert result.Operation == 'Command'
#     assert result.message[0].CustomMode == resultvalue
#     assert result.message[0].CustomModes == resultmsg
#     assert 'CustomMode' in result.message[1].Operation
#
#
# @pytest.mark.parametrize("test_query, resultvalue, resultmsg", [
#     ("217 7 01 68 b3 da e0 00 87",  "18", ["900.000123456790"]),
#     ("224 7 00 00 00 00 00 00 00",  "19", ["Empty"]),
#     # ("98 7 01 e4 be fc 00 01 ef",  "1", ["990.000004160807"]),
# ])
# @pytest.mark.pethubcommand
# def test_petdoor_status_prov(global_variables, request, test_query, resultvalue, resultmsg):  # Set Petdoor to modes
#     log.info('TEST: ' + request.node.name)
#     result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0280 132 1 " + test_query)
#     log.info(json_print(result))
#     assert result.Operation == 'Status'
#     assert result.message[0].TagOffset == resultvalue
#     assert result.message[0].Tag == resultmsg
#     assert 'Tag' in result.message[1].Operation


# Curfew on
# 6058bbb2 1000 2 36 1 04
# 6058bbb2 1000 2 519 6 02 0b 32 0b 37 00

#Curfew off
# 6058bbd9 1000 2 36 1 00
# 6058bbd9 1000 2 519 6 01 0b 32 0b 37 00

"""
Boot Message
60586808 0200 132 29 0 16 03 76 02 01 00 01 00 01 00 02 00 25 00 01 00 00
60586808 0200 132 29 0 16 03 76 02 01 00 01 00 01 00 02 00 25 00 01 00 00
60586809 0210 132 30 16 16 00 01 00 00 00 00 00 10 00 04 00 00 00 7f 97 98
60586809 0210 132 30 16 16 00 01 00 00 00 00 00 10 00 04 00 00 00 7f 97 98
60586809 0220 132 31 32 1 00
60586809 0220 132 31 32 1 00
6058680a 0230 132 32 36 16 00 00 02 01 02 00 00 84 00 00 00 00 00 00 00 00
6058680a 0230 132 32 36 16 00 00 02 01 02 00 00 84 00 00 00 00 00 00 00 00
6058680a 0240 132 33 52 16 00 00 00 00 00 00 00 03 05 00 00 00 00 00 00 00
6058680a 0240 132 33 52 16 00 00 00 00 00 00 00 03 05 00 00 00 00 00 00 00
6058680b 0250 132 34 68 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
6058680b 0250 132 34 68 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
6058680b 0260 132 35 84 7 00 00 00 00 00 14 85
6058680b 0260 132 35 84 7 00 00 00 00 00 14 85
6058680c 0270 132 36 91 7 04 87 0c c3 00 49 b6
6058680c 0270 132 36 91 7 04 87 0c c3 00 49 b6
6058680d 0280 132 37 98 7 01 e4 be fc 00 01 ef
6058680d 0280 132 37 98 7 01 e4 be fc 00 01 ef
6058680d 0290 132 38 105 7 01 8d 47 7a a0 01 97
6058680d 0290 132 38 105 7 01 8d 47 7a a0 01 97
6058680e 02a0 132 39 112 7 00 00 00 00 00 00 00
6058680e 02a0 132 39 112 7 00 00 00 00 00 00 00
6058680e 02b0 132 40 119 7 00 00 00 00 00 00 00
6058680e 02b0 132 40 119 7 00 00 00 00 00 00 00
6058680f 02c0 132 41 126 7 00 00 00 00 00 00 00
6058680f 02c0 132 41 126 7 00 00 00 00 00 00 00
6058680f 02d0 132 42 133 7 00 00 00 00 00 00 00
6058680f 02d0 132 42 133 7 00 00 00 00 00 00 00
60586810 02e0 132 43 140 7 00 00 00 00 00 00 00
60586810 02e0 132 43 140 7 00 00 00 00 00 00 00
60586811 02f0 132 44 147 7 00 00 00 00 00 00 00
60586811 02f0 132 44 147 7 00 00 00 00 00 00 00
60586811 0300 132 45 154 7 00 00 00 00 00 00 00
60586811 0300 132 45 154 7 00 00 00 00 00 00 00
60586812 0310 132 46 161 7 00 00 00 00 00 00 00
60586812 0310 132 46 161 7 00 00 00 00 00 00 00
60586812 0320 132 47 168 7 00 00 00 00 00 00 00
60586812 0320 132 47 168 7 00 00 00 00 00 00 00
60586813 0330 132 48 175 7 00 00 00 00 00 00 00
60586813 0330 132 48 175 7 00 00 00 00 00 00 00
60586813 0340 132 49 182 7 00 00 00 00 00 00 00
60586813 0340 132 49 182 7 00 00 00 00 00 00 00
60586814 0350 132 50 189 7 00 00 00 00 00 00 00
60586814 0350 132 50 189 7 00 00 00 00 00 00 00
60586815 0360 132 51 196 7 00 00 00 00 00 00 00
60586815 0360 132 51 196 7 00 00 00 00 00 00 00
60586815 0370 132 52 203 7 00 00 00 00 00 00 00
60586815 0370 132 52 203 7 00 00 00 00 00 00 00
60586816 0380 132 53 210 7 00 00 00 00 00 00 00
60586816 0380 132 53 210 7 00 00 00 00 00 00 00
60586816 0390 132 54 217 7 00 00 00 00 00 00 00
60586816 0390 132 54 217 7 00 00 00 00 00 00 00
60586817 03a0 132 55 224 7 00 00 00 00 00 00 00
60586817 03a0 132 55 224 7 00 00 00 00 00 00 00
60586817 03b0 132 56 231 7 00 00 00 00 00 00 00
60586817 03b0 132 56 231 7 00 00 00 00 00 00 00
60586818 03c0 132 57 238 7 00 00 00 00 00 00 00
60586818 03d0 132 58 245 7 00 00 00 00 00 00 00
60586818 03c0 132 57 238 7 00 00 00 00 00 00 00
60586818 03d0 132 58 245 7 00 00 00 00 00 00 00
60586819 03e0 132 59 252 7 00 00 00 00 00 00 00
60586819 03e0 132 59 252 7 00 00 00 00 00 00 00
60586819 03f0 132 60 259 7 00 00 00 00 00 00 00
60586819 03f0 132 60 259 7 00 00 00 00 00 00 00
6058681a 0400 132 61 266 7 00 00 00 00 00 00 00
6058681a 0400 132 61 266 7 00 00 00 00 00 00 00
6058681b 0410 132 62 273 7 00 00 00 00 00 00 00
6058681b 0410 132 62 273 7 00 00 00 00 00 00 00
6058681b 0420 132 63 280 7 00 00 00 00 00 00 00
6058681b 0420 132 63 280 7 00 00 00 00 00 00 00
6058681c 0430 132 64 287 7 00 00 00 00 00 00 00
6058681c 0430 132 64 287 7 00 00 00 00 00 00 00
6058681c 0440 132 65 294 7 00 00 00 00 00 00 00
6058681c 0440 132 65 294 7 00 00 00 00 00 00 00
6058681d 0450 132 66 301 7 00 00 00 00 00 00 00
6058681d 0450 132 66 301 7 00 00 00 00 00 00 00
6058681d 0460 132 67 308 7 00 00 00 00 00 00 00
6058681d 0460 132 67 308 7 00 00 00 00 00 00 00
6058681e 0470 132 68 315 6 03 0c 01 0c 02 01
6058681e 0470 132 68 315 6 03 0c 01 0c 02 01
6058681e 0480 132 69 321 6 01 0b 1e 0c 02 01
6058681e 0480 132 69 321 6 01 0b 1e 0c 02 01
6058681f 0490 132 70 327 6 01 0b 2d 0c 03 01
6058681f 0490 132 70 327 6 01 0b 2d 0c 03 01
60586820 04a0 132 71 333 6 01 0b 2d 0c 03 01
60586820 04a0 132 71 333 6 01 0b 2d 0c 03 01
60586820 04b0 132 72 339 6 01 0b 2d 0c 03 01
60586820 04b0 132 72 339 6 01 0b 2d 0c 03 01
60586821 04c0 132 73 345 6 01 0b 2d 0c 03 01
60586821 04c0 132 73 345 6 01 0b 2d 0c 03 01
60586821 04d0 132 74 351 6 01 0b 2d 0c 03 01
60586821 04d0 132 74 351 6 01 0b 2d 0c 03 01
60586822 04e0 132 75 357 6 01 0b 2d 0c 03 01
60586822 04e0 132 75 357 6 01 0b 2d 0c 03 01
60586822 04f0 132 76 363 6 01 0b 2d 0c 03 01
60586822 04f0 132 76 363 6 01 0b 2d 0c 03 01
60586823 0500 132 77 369 6 01 0b 2d 0c 03 01
60586823 0500 132 77 369 6 01 0b 2d 0c 03 01
60586823 0510 132 78 375 6 01 0b 2d 0c 03 01
60586823 0510 132 78 375 6 01 0b 2d 0c 03 01
60586824 0520 132 79 381 6 01 0b 2d 0c 03 01
60586824 0520 132 79 381 6 01 0b 2d 0c 03 01
60586824 0530 132 80 387 6 01 0b 2d 0c 03 01
60586824 0530 132 80 387 6 01 0b 2d 0c 03 01
60586825 0540 132 81 393 6 01 0b 2d 0c 03 01
60586825 0540 132 81 393 6 01 0b 2d 0c 03 01
60586826 0550 132 82 399 6 01 0b 2d 0c 03 01
60586826 0550 132 82 399 6 01 0b 2d 0c 03 01
60586826 0560 132 83 405 6 01 0b 2d 0c 03 01
60586826 0560 132 83 405 6 01 0b 2d 0c 03 01
60586827 0570 132 84 411 6 01 0b 2d 0c 03 01
60586827 0570 132 84 411 6 01 0b 2d 0c 03 01
60586827 0580 132 85 417 6 01 0b 2d 0c 03 01
60586827 0580 132 85 417 6 01 0b 2d 0c 03 01
60586828 0590 132 86 423 6 01 0b 2d 0c 03 01
60586828 0590 132 86 423 6 01 0b 2d 0c 03 01
60586828 05a0 132 87 429 6 01 0b 2d 0c 03 01
60586828 05a0 132 87 429 6 01 0b 2d 0c 03 01
60586829 05b0 132 88 435 6 01 0b 2d 0c 03 01
60586829 05c0 132 89 441 6 01 0b 2d 0c 03 01
60586829 05b0 132 88 435 6 01 0b 2d 0c 03 01
60586829 05c0 132 89 441 6 01 0b 2d 0c 03 01
6058682a 05d0 132 90 447 6 01 0b 2d 0c 03 01
6058682a 05d0 132 90 447 6 01 0b 2d 0c 03 01
6058682a 05e0 132 91 453 6 01 0b 2d 0c 03 01
6058682a 05e0 132 91 453 6 01 0b 2d 0c 03 01
6058682b 05f0 132 92 459 6 01 0b 2d 0c 03 01
6058682b 05f0 132 92 459 6 01 0b 2d 0c 03 01
6058682c 0600 132 93 459 6 01 0b 2d 0c 03 01
6058682c 0600 132 93 459 6 01 0b 2d 0c 03 01
6058682c 0610 132 94 465 6 01 0b 2d 0c 03 01
6058682c 0610 132 94 465 6 01 0b 2d 0c 03 01
6058682d 0620 132 95 465 6 01 0b 2d 0c 03 01
6058682d 0620 132 95 465 6 01 0b 2d 0c 03 01
6058682d 0630 132 96 471 6 01 0b 2d 0c 03 01
6058682d 0630 132 96 471 6 01 0b 2d 0c 03 01
6058682e 0640 132 97 477 6 01 0b 2d 0c 03 01
6058682e 0640 132 97 477 6 01 0b 2d 0c 03 01
6058682e 0650 132 98 483 6 01 0b 2d 0c 03 01
6058682e 0650 132 98 483 6 01 0b 2d 0c 03 01
6058682f 0660 132 99 483 6 01 0b 2d 0c 03 01
6058682f 0660 132 99 483 6 01 0b 2d 0c 03 01
60586830 0670 132 100 489 6 01 0b 2d 0c 03 01
60586830 0670 132 100 489 6 01 0b 2d 0c 03 01
60586830 0680 132 101 495 6 01 0b 2d 0c 03 01
60586830 0680 132 101 495 6 01 0b 2d 0c 03 01
60586831 0690 132 102 501 6 01 0b 2d 0c 03 01
60586831 0690 132 102 501 6 01 0b 2d 0c 03 01
60586831 06a0 132 103 507 6 01 0b 2d 0c 03 01
60586831 06a0 132 103 507 6 01 0b 2d 0c 03 01
60586832 06b0 132 104 513 6 01 0b 2d 0c 03 01
60586832 06b0 132 104 513 6 01 0b 2d 0c 03 01
60586832 06c0 132 105 519 6 01 0b 1e 0b 0f 00
60586832 06c0 132 105 519 6 01 0b 1e 0b 0f 00
60586833 06d0 132 106 525 3 01 0b 61
60586833 06d0 132 106 525 3 01 0b 61
60586834 06e0 132 107 528 3 16 11 81
60586834 06e0 132 107 528 3 16 11 81
60586834 06f0 132 108 531 3 00 02 a4
60586834 06f0 132 108 531 3 00 02 a4
60586835 0700 132 109 534 3 00 00 00
60586835 0700 132 109 534 3 00 00 00
60586835 0710 132 110 537 3 a4 01 08
60586835 0710 132 110 537 3 a4 01 08
60586836 0720 132 111 540 3 95 01 c8
60586836 0720 132 111 540 3 95 01 c8
60586836 0730 132 112 543 3 00 00 00
60586836 0730 132 112 543 3 00 00 00
60586837 0740 132 113 546 3 00 00 00
60586837 0740 132 113 546 3 00 00 00
60586838 0750 132 114 549 3 00 00 00
60586838 0750 132 114 549 3 00 00 00
60586838 0760 132 115 552 3 00 00 00
60586838 0760 132 115 552 3 00 00 00
60586839 0770 132 116 555 3 00 00 00
60586839 0770 132 116 555 3 00 00 00
60586839 0780 132 117 558 3 00 00 00
60586839 0780 132 117 558 3 00 00 00
6058683a 0790 132 118 561 3 00 00 00
6058683a 0790 132 118 561 3 00 00 00
6058683a 07a0 132 119 564 3 00 00 00
6058683a 07a0 132 119 564 3 00 00 00
6058683b 07b0 132 120 567 3 00 00 00
6058683b 07b0 132 120 567 3 00 00 00
6058683c 07c0 132 121 570 3 00 00 00
6058683c 07c0 132 121 570 3 00 00 00
6058683c 07d0 132 122 573 3 00 00 00
6058683c 07d0 132 122 573 3 00 00 00
6058683d 07e0 132 123 576 3 00 00 00
6058683d 07e0 132 123 576 3 00 00 00
6058683d 07f0 132 124 579 3 00 00 00
6058683d 07f0 132 124 579 3 00 00 00
6058683e 0800 132 125 582 3 00 00 00
6058683e 0800 132 125 582 3 00 00 00
6058683f 0810 132 126 585 3 00 00 00
6058683f 0810 132 126 585 3 00 00 00
6058683f 0820 132 127 588 3 00 00 00
6058683f 0820 132 127 588 3 00 00 00
60586840 0830 132 128 591 3 00 00 00
60586840 0830 132 128 591 3 00 00 00
60586840 0840 132 129 594 3 00 00 00
60586840 0840 132 129 594 3 00 00 00
60586841 0850 132 130 597 3 00 00 00
60586841 0850 132 130 597 3 00 00 00
60586841 0860 132 131 600 3 00 00 00
60586841 0860 132 131 600 3 00 00 00
60586842 0870 132 132 603 3 00 00 00
60586842 0870 132 132 603 3 00 00 00
60586842 0880 132 133 606 3 00 00 00
60586842 0880 132 133 606 3 00 00 00
60586843 0890 132 134 609 3 00 00 00
60586843 0890 132 134 609 3 00 00 00
60586844 08a0 132 135 612 3 00 00 00
60586844 08a0 132 135 612 3 00 00 00
60586844 08b0 132 136 615 3 00 00 00
60586844 08b0 132 136 615 3 00 00 00
60586845 08c0 132 137 618 3 00 00 00
60586845 08c0 132 137 618 3 00 00 00
60586845 08d0 132 138 621 9 13 31 b2 00 00 00 00 00 00
60586845 08d0 132 138 621 9 13 31 b2 00 00 00 00 00 00

"""