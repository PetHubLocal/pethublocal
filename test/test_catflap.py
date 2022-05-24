"""
    Test Cat Flap
"""
import json
import sys
import pytest

sys.path.append('..')
import pethublocal.message as p
import pethublocal.generate as g
import pethublocal as log
from pethublocal.functions import config_load, json_print
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
    return result


@pytest.fixture
def global_variables():
    pytest.hub = 'H010-0123456'
    pytest.mac = '6666666666666666'
    pytest.devtype = 6  # Device Type 6 = CatFlap


def setup_module():
    log.info('setup')


def teardown_module():
    log.info('teardown')
    with open('pethubconfig-updated.json', 'w') as fp:
        json.dump(pethubconfig, fp, indent=4)


# Test Status Messages
@pytest.mark.pethubstatus
def test_catflap_battery(global_variables, request):
    testmessage = "5fef6320 0050 126 18 0c 00 05 00 b8 c8 42 54 04 17 00 00 d3 0c 00 00 25 01 00 00 0e 00 42 00"
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, testmessage)
    # assert result.message[-1].Operation[0] == 'Battery'
    assert result.message[0].data.msg == '0c'
    assert result.message[0].data.counter == '5'
    assert result.message[0].Operation == 'Battery'
    assert result.message[0].Battery == "5.892"


@pytest.mark.parametrize("provhex, lockstate", [
    ("03", "Keepin"),    # Lock State - KeepIn
    ("06", "Unlocked"),  # Lock State - Unlocked
])
@pytest.mark.pethubstatus
def test_catflap_status_curfewlockstate(global_variables, request, provhex, lockstate):
    testmessage = "5fef6320 1000 126 1e 0d 00 01 00 b8 c8 42 54 ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 fc 00 02 00 06 " + provhex
    result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
    assert result.Operation == 'Command'
    # assert result.message[-1].Operation[0] == 'CurfewLockState'
    assert result.message[0].frametimestamp == "2021-01-01 12:34:56"  # Timestamp
    assert result.message[0].data.msg == '0d'  # Message type
    assert result.message[0].data.counter == '1'  # Counter
    assert result.message[0].LockState == lockstate  # State


@pytest.mark.parametrize("operation,provhex,animal,lockstate, offset, tagstate", [
    ("LockState", "00 00 00 00 00 00 07 03 00 02", "Empty", "Keepin", "0", ""),    # Lock State - KeepIn
    ("LockState", "00 00 00 00 00 00 07 04 00 02", "Empty", "Locked", "0", ""),    # Lock State - Locked
    ("LockState", "00 00 00 00 00 00 07 05 00 02", "Empty", "Keepout", "0", ""),   # Lock State - KeepOut
    ("LockState", "00 00 00 00 00 00 07 06 00 02", "Empty", "Unlocked", "0", ""),  # Lock State - Unlocked
    ("Tag", "14 cd 5b 07 00 e1 01 02 01 00", "900.000123456788", "Normal", "1", "Enabled"),   # Tag 1
    ("Tag", "16 cd 5b 07 00 e1 01 03 02 00", "900.000123456790", "Keepin", "2", "Enabled"),   # Tag 2
    ("Tag", "17 cd 5b 07 00 e1 01 02 03 01", "900.000123456791", "Normal", "3", "Disabled"),  # Tag 3
    ("Tag", "18 cd 5b 07 00 e1 01 03 04 01", "900.000123456792", "Keepin", "4", "Disabled"),  # Tag 4
    ("Tag", "00 00 00 00 00 00 07 06 05 00", "Empty", "Unlocked", "5", "Enabled"),   # Empty
    ("Tag", "00 00 00 00 00 00 07 06 0a 00", "Empty", "Unlocked", "10", "Enabled"),  # Empty
    ("Tag", "00 00 00 00 00 00 07 06 1e 00", "Empty", "Unlocked", "30", "Enabled"),  # Empty
])
@pytest.mark.pethubstatus
def test_catflap_status_tagprovisioning_and_doorlocking(global_variables, request, operation, provhex, animal, lockstate, offset, tagstate):
    testmessage = "5fef6320 0000 126 12 11 00 01 00 b8 c8 42 54 " + provhex
    result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
    assert result.Operation == 'Status'
    # assert result.message[-1].Operation[0] == operation
    assert result.message[0].Operation == operation
    assert result.message[0].TagOffset == offset
    assert result.message[0].LockState == lockstate
    # if result.message[-1].Operation[0] == 'Tag' and result.message[0].Tag not in ['Empty']:
    #     assert result.message[0].Animal == animal


@pytest.mark.parametrize("taghex,directionhex,animal,direction", [
    ("14 cd 5b 07 00 e1 01", "00 00", "900.000123456788", "Outside"),        # Animal went out
    ("16 cd 5b 07 00 e1 01", "01 01", "900.000123456790", "Inside"),         # Animal came in
    ("17 cd 5b 07 00 e1 01", "02 00", "900.000123456791", "Lookedout"),  # Animal Looked out but didn't go out
    ("18 cd 5b 07 00 e1 01", "02 01", "900.000123456792", "Lookedin"),   # Animal Looked in but didn't come in
    ("00 00 00 00 00 00 00", "02 02", "Empty", "Status2"),               # Status 2, this happens a lot with above messages
    ("00 00 00 00 00 00 00", "01 02", "Empty", "Status1"),               # Random Status message I don't know if this happens but added for completeness
])
@pytest.mark.pethubstatus
def test_catflap_status_petmovement(global_variables, request, taghex, directionhex, animal, direction):
    testmessage="5fef6320 0110 126 1e 13 00 01 01 b8 c8 42 54 00 00 00 00 02 16 00 00 "+directionhex+" "+taghex+" 01 00 00 00 00"
    result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
    assert result.Operation == 'Status'
    # assert result.message[-1].Operation[0] == 'PetMovement'
    assert result.message[0].frametimestamp == "2021-01-01 12:34:56"  # Timestamp
    assert result.message[0].data.msg == '13'  # Message type
    assert result.message[0].Direction == direction
    # if result.message[0].Tag not in ['Empty']:
    #     assert result.message[0].Animal == animal


# Test Command Messages
@pytest.mark.parametrize("test_acks", [
    ("09"),  # Boot message 09
    ("0b"),  # Unknown 0b message
    ("0c"),  # Battery state change
    ("10"),  # Boot message 10
    ("11"),  # Tag provisioning
    ("13"),  # Pet Movement
    ("16"),  # Status 16 message
    ("17")   # Boot message 17
])
@pytest.mark.pethubcommand
def test_catflap_command_acknowledge(global_variables, request, test_acks):
    testmessage = "5fef6320 1000 127 00 00 0c 00 b8 c8 42 54 " + test_acks + " 00 00"
    result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
    assert result.Operation == 'Command'
    # assert result.message[-1].Operation[0] == 'Ack'
    assert result.message[0].data.msg == '00'
    assert result.message[0].data.counter == '12'
    assert result.message[0].Operation == 'Ack'
    assert result.message[0].Message == test_acks


@pytest.mark.parametrize("test_query,type,subdata", [
    ("09 00 ff", "09", "00ff"),  # Boot message 09
    ("10 00", "10", "00"),  # Boot message 10
    ("11 00 ff", "11", "00ff"),  # Tag provisioned
    ("17 00 00", "17", "0000"),  # Boot message  17
    ("0b 00", "0b", "00"),  # Unknown 0b
    ("0c 00", "0c", "00"),  # Battery state
])
@pytest.mark.pethubcommand
def test_catflap_command_query(global_variables, request, test_query, type, subdata):
    testmessage = "5fef6320 1000 127 01 00 01 01 b8 c8 42 54 " + test_query
    result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
    assert result.Operation == 'Command'
    # assert result.message[-1].Operation[0] == 'Query'
    assert result.message[0].data.msg == '01'
    assert result.message[0].data.counter == '257'
    assert result.message[0].Operation == 'Query'
    assert result.message[0].Type == type
    assert result.message[0].SubData == subdata


@pytest.mark.pethubcommand
def test_catflap_command_curfewset(global_variables, request):
    testmessage = "61649b3f 1000 127 12 00 01 00 b8 c8 42 54 00 00 00 00 00 00 07 00 80 07 42 54 80 17 42 54 03 c0 43 42 54 80 50 42 54 03 00 00 42 00 00 00 42 00 06 00 00 42 00 00 00 42 00 06"
    result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
    assert result.Operation == 'Command'
    # assert result.message[-1].Operation[0] == 'Curfew'
    # assert result.message[0].frametimestamp == "2021-01-01 12:34:56"  # Timestamp
    assert result.message[0].data.msg == '12'  # Message type
    assert result.message[0].data.counter == '1'  # Counter
    assert len(result.message[0].Curfew) == 2  # Number of curfew entries
    assert result.message[0].Curfew[0].State == 3  # Curfew Enabled
    # assert result.message[0].Curfew[0].Start == "00:30"  # Curfew Start in UTC
    # assert result.message[0].Curfew[0].End == "01:30"  # Curfew End in UTC
    assert result.message[0].Curfew[1].State == 3  # Curfew Enabled
    # assert result.message[0].Curfew[1].Start == "04:15"  # Curfew Start in UTC
    # assert result.message[0].Curfew[1].End == "05:02"  # Curfew End in UTC


@pytest.mark.pethubcommand
def test_catflap_command_curfewclear(global_variables, request):
    testmessage = "5fef6320 1000 127 12 00 01 00 b8 c8 42 54 00 00 00 00 00 00 07 00 00 00 42 00 00 00 42 00 06 00 00 42 00 00 00 42 00 06 00 00 42 00 00 00 42 00 06 00 00 42 00 00 00 42 00 06"
    result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
    assert result.Operation == 'Command'
    # assert result.message[-1].Operation[0] == 'Curfew'
    # assert result.message[0].frametimestamp == "2021-01-01 12:34:56"  # Timestamp
    assert result.message[0].data.msg == '12'  # Message type
    assert result.message[0].data.counter == '1'  # Counter
    assert len(result.message[0].Curfew) == 0  # Number of curfew entries


# @pytest.mark.pethubcommand
# def test_catflap_command_curfewclear(global_variables, request):
#     log.info('TEST: ' + request.node.name)
#     testmessage="61674312 1000 127 00 00 02 00 dd 98 9c 56 07 00 00"
#     log.info('Message: ' + testmessage)
#     result = run_test(request.node.name, pethubconfig,  pytest.hub + '/messages/' + pytest.mac, testmessage)
#     log.info(json_print(result))
#     assert result.Operation == 'Command'
#     # assert result.message[-1].Operation[0] == 'Curfew'
    # assert result.message[0].frametimestamp == "2021-01-01 12:34:56"  # Timestamp
    # assert result.message[0].data.msg == '12'  # Message type
    # assert result.message[0].data.counter == '1'  # Counter
    # assert len(result.message[0].Curfew) == 0  # Number of curfew entries
    #
    #
