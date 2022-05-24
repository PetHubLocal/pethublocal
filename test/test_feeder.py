# Test Feeder
import pytest
import json
import sys

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

if TESTING_MQTT and 'MQTTHost' in pethubconfig['config']:
    host = pethubconfig['config']['MQTTHost'] if 'MQTTHost' in pethubconfig['config'] else '127.0.0.1'
    port = pethubconfig['config']['MQTTPort'] if 'MQTTPort' in pethubconfig['config'] else 1883
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
    pytest.mac = '4444444444444444'
    pytest.devtype = 4               # Device Type 4 = Feeder


def setup_module():
    log.info('setup')


def teardown_module():
    log.info('teardown')
    print('Current pethubconfig')
    with open('pethubconfig-updated.json', 'w') as fp:
        json.dump(pethubconfig, fp, indent=4)

#Test Status Messages
@pytest.mark.pethubstatus
def test_feeder_battery(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 0050 126 18 0c 00 05 00 b8 c8 42 54 ae 17 00 00 d3 0c 00 00 25 01 00 00 0e 00 42 00")
    assert result.message[0].Operation == 'Battery'
    assert result.message[0].data.msg == '0c'
    assert result.message[0].data.counter == '5'
    assert result.message[0].Operation == 'Battery'
    assert result.message[0].Battery == "6.062"

@pytest.mark.parametrize("operation, provhex, animal, lockstate, offset, tagstate", [
    ("Tag", "14 cd 5b 07 00 e1 01 02 01 00", "900.000123456788", "Normal", "1", "Enabled"),  # Tag 1
    ("Tag", "16 cd 5b 07 00 e1 01 02 02 01", "900.000123456790", "Normal", "2", "Disabled"),  # Tag 1
    ("Tag", "00 00 00 00 00 00 07 06 02 00", "Empty", "Unlocked", "2", "Enabled"),  # Tag 1
    ("Tag", "00 00 00 00 00 00 07 06 0a 00", "Empty", "Unlocked", "10", "Enabled"),  # Tag 1
    ("Tag", "00 00 00 00 00 00 07 06 1e 00", "Empty", "Unlocked", "30", "Enabled"),  # Tag 1
])
@pytest.mark.pethubcommand
def test_feeder_status_tag(global_variables, request, operation, provhex, animal, lockstate, offset, tagstate):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0000 126 12 11 00 01 00 b8 c8 42 54 " + provhex)
    assert result.Operation == 'Status'
    assert result.message[0].Operation == operation
    assert result.message[0].Operation == operation
    assert result.message[0].LockState == lockstate
    assert result.message[0].TagOffset == offset
    assert result.message[0].TagState == tagstate
    # if result.message[0].Operation == 'Tag' and result.message[0].Tag not in ['Empty']:
    #     assert result.message[0].Animal == animal

@pytest.mark.pethubstatus
def test_feeder_animal_open(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 0010 126 29 18 00 c9 00 b8 c8 42 54 14 cd 5b 07 00 e1 01 00 00 00 02 79 fb ff ff 00 00 00 00 d0 00 00 00 00 00 00 00 06 00 25 01 00 00")
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].data.msg == '18'
    assert result.message[0].data.counter == '201'
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].Action == "Animal_Open"
    assert result.message[0].Time == "0"
    assert result.message[0].Bowl1From == "-11.59"
    assert result.message[0].Bowl1To == "0.0"
    assert result.message[0].Bowl1Delta == "11.59"
    assert result.message[0].Bowl2From == "2.08"
    assert result.message[0].Bowl2To == "0.0"
    assert result.message[0].Bowl2Delta == "-2.08"
    # assert result.message[0].Tag == "900.000123456788"

@pytest.mark.pethubstatus
def test_feeder_animal_closed(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 0020 126 29 18 00 ca 00 b8 c8 42 54 14 cd 5b 07 00 e1 01 01 0b 00 02 79 fb ff ff 8c fb ff ff d0 00 00 00 d1 00 00 00 07 00 25 01 00 00")
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].data.msg == '18'
    assert result.message[0].data.counter == '202'
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].Action == "Animal_Closed"
    assert result.message[0].Time == "11"
    assert result.message[0].Bowl1From == "-11.59"
    assert result.message[0].Bowl1To == "-11.4"
    assert result.message[0].Bowl1Delta == "0.19"
    assert result.message[0].Bowl2From == "2.08"
    assert result.message[0].Bowl2To == "2.09"
    assert result.message[0].Bowl2Delta == "0.01"
    assert result.message[0].Tag == ["900.000123456788"]

@pytest.mark.pethubstatus
def test_feeder_manual_open(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 0030 126 29 18 00 04 00 b8 c8 42 54 01 02 03 04 05 06 07 04 00 00 02 b9 0e 00 00 00 00 00 00 60 00 00 00 00 00 00 00 ee 00 24 01 00 00")
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].data.msg == '18'
    assert result.message[0].data.counter == '4'
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].Action == 'Manual_Open'
    assert result.message[0].Time == '0'
    assert result.message[0].Bowl1From == "37.69"
    assert result.message[0].Bowl1To == "0.0"
    assert result.message[0].Bowl1Delta == "-37.69"
    assert result.message[0].Bowl2From == "0.96"
    assert result.message[0].Bowl2To == "0.0"
    assert result.message[0].Bowl2Delta == "-0.96"
    # assert result.message[0].Tag == "Manual"

@pytest.mark.pethubstatus
def test_feeder_manual_close(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 0040 126 29 18 00 04 00 b8 c8 42 54 01 02 03 04 05 06 07 05 52 00 02 b9 0e 00 00 3a 00 00 00 60 00 00 00 d3 1a 00 00 ef 00 25 01 00 00")
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].data.msg == '18'
    assert result.message[0].data.counter == '4'
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].Action == 'Manual_Closed'
    assert result.message[0].Time == "82"
    assert result.message[0].Bowl1From == "37.69"
    assert result.message[0].Bowl1To == "0.58"
    assert result.message[0].Bowl1Delta == "-37.11"
    assert result.message[0].Bowl2From == "0.96"
    assert result.message[0].Bowl2To == "68.67"
    assert result.message[0].Bowl2Delta == "67.71"
    # assert result.message[0].Tag == "Manual"

@pytest.mark.pethubstatus
def test_feeder_zero_button(global_variables, request): #Zero feeder using button on the back when the feeder is open
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 0260 126 29 18 00 08 00 b8 c8 42 54 01 02 03 04 05 06 07 06 00 00 02 00 00 00 00 d0 fa ff ff 00 00 00 00 51 ff ff ff 07 00 24 01 00 00")
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].data.msg == '18'
    assert result.message[0].data.counter == '8'
    assert result.message[0].Operation == 'Feed'
    assert result.message[0].Action == 'Zero_Both'
    assert result.message[0].Bowl1From == "0.0"
    assert result.message[0].Bowl1To == "-13.28"
    assert result.message[0].Bowl1Delta == "-13.28"
    assert result.message[0].Bowl2From == "0.0"
    assert result.message[0].Bowl2To == "-1.75"
    assert result.message[0].Bowl2Delta == "-1.75"
    # assert result.message[0].Tag == "Manual"

@pytest.mark.pethubstatus
def test_feeder_status_132(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0010 132 40 33 3 9f 05 1e")
    assert result.Operation == 'Status'
    assert result.message[0].Operation == "Data132Battery"
    assert result.message[0].Battery == "5.685"
    assert result.message[0].Time == "05:30"

#Test Command Messages
@pytest.mark.parametrize("test_acks", [
    ("09"), # Boot message 09
    ("0b"), # Unknown 0b message
    ("0c"), # Battery state change
    ("10"), # Boot message 10
    ("11"), # Tag provisioning
    ("16"), # Status 16 message
    ("17"), # Boot message 17
    ("18"), # Feeder state change
])
@pytest.mark.pethubcommand
def test_feeder_command_acknowledge(global_variables, request, test_acks):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 1000 127 00 00 0c 00 b8 c8 42 54 " + test_acks + " 00 00")
    assert result.Operation == 'Command'
    assert result.message[0].Operation == 'Ack'
    assert result.message[0].data.msg == '00'
    assert result.message[0].data.counter == '12'
    assert result.message[0].Operation == 'Ack'
    assert result.message[0].Message == test_acks

@pytest.mark.parametrize("test_query,type,subdata", [
    ("09 00 ff","09","00ff"),    # Boot message 09
    ("10 00", "10", "00"),       # Boot message 10
    ("11 00 ff", "11", "00ff"),  # Tag provisioned
    ("17 00 00", "17", "0000"),  # Boot message  17
    ("0b 00", "0b", "00"),       # Unknown 0b
    ("0c 00", "0c", "00"),       # Battery state
])
@pytest.mark.pethubcommand
def test_feeder_command_query(global_variables, request, test_query, type, subdata):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 1000 127 01 00 01 01 b8 c8 42 54 " + test_query)
    assert result.Operation == 'Command'
    assert result.message[0].Operation == 'Query'
    assert result.message[0].data.msg == '01'
    assert result.message[0].data.counter == '257'
    assert result.message[0].Operation == 'Query'
    assert result.message[0].Type == type
    assert result.message[0].SubData == subdata

@pytest.mark.pethubcommand
def test_feeder_command_time(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 1000 127 07 00 01 00 b8 c8 42 54 00 00 00 00 07")
    assert result.Operation == 'Command'
    assert result.message[0].Operation == 'Time'
    assert result.message[0].data.msg == '07'
    assert result.message[0].data.counter == '1'
    assert result.message[0].Operation == 'Time'
    assert result.message[0].Type == "0000000007"

@pytest.mark.parametrize("test_generate,genvalue,genresponse", [
    ("SetBowl1Target", "10", " 0a e8 03 00 00"),     # Set Bowl1 Target Weight
    ("SetBowl2Target", "25", " 0b c4 09 00 00"),     # Set Bowl2 Target Weight
    ("SetBowlCount", "One", " 0c 01 00 00 00"),     # Set Bowl Count
    ("SetBowlCount", "Two", " 0c 02 00 00 00"),     # Set Bowl Count
    ("SetCloseDelay", "Fast", " 0d 00 00 00 00"),   # 0 Seconds
    ("SetCloseDelay", "Normal", " 0d a0 0f 00 00"), # 4 Seconds "0fa0" = 4000
    ("SetCloseDelay", "Slow", " 0d 20 4e 00 00"),   # 20 Seconds "4e20" = 20000
    ("Set12", "500", " 12 f4 01 00 00"),            # Set Message 12
    ("Custom-Intruder", "", " 14 00 01 00 00"),      # Set Custom Mode - Intruder
    ("Custom-Geniuscat", "", " 14 80 00 00 00"),     # Set Custom Mode - GeniusCat
])
@pytest.mark.pethubcommand
def test_feeder_command_updatestate(global_variables, request, test_generate, genvalue, genresponse):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 1000 127 09 00 12 01 b8 c8 42 54" + genresponse)
    assert result.Operation == 'Command'
    assert result.message[0].Operation == 'UpdateState'
    assert result.message[0].data.msg == '09'
    assert result.message[0].data.counter == '274'
    assert result.message[0].Operation == 'UpdateState'
    assert result.message[0].SubOperation == test_generate
    if test_generate in ['SetBowl1Target', 'SetBowl2Target']:
        assert result.message[0].Weight == genvalue
    if test_generate == 'SetBowlCount':
        assert result.message[0].Bowls == genvalue
    if test_generate == 'SetCloseDelay':
        assert result.message[0].Delay == genvalue
    if test_generate == 'Set12':
        assert result.message[0].Value == genvalue
    if test_generate == 'Set12':
        assert result.message[0].Value == genvalue

@pytest.mark.parametrize("test_zeroscale,zerovalue", [
    ("Zerobowl1", "01"),   # Zero Bowl1
    ("Zerobowl2", "02"),   # Zero Bowl2
    ("Zeroboth", "03"),    # Zero Both
])
@pytest.mark.pethubcommand
def test_feeder_command_zeroscale(global_variables, request, test_zeroscale, zerovalue):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 1000 127 0d 00 12 00 b8 c8 42 54 00 19 00 00 00 03 00 00 00 00 01 " + zerovalue)
    assert result.Operation == 'Command'
    assert result.message[0].Operation == 'ZeroScales'
    assert result.message[0].Operation == 'ZeroScales'
    assert result.message[0].Scale == test_zeroscale


@pytest.mark.parametrize("operation,provhex,animal,lockstate, offset, tagstate", [
    ("Tag", "14 cd 5b 07 00 e1 01 02 01 00", "900.000123456788", "Normal", "1", "Enabled"),  # Tag 1
    ("Tag", "16 cd 5b 07 00 e1 01 02 02 01", "900.000123456790", "Normal", "2", "Disabled"),  # Tag 1
    ("Tag", "00 00 00 00 00 00 07 06 03 00", "Empty", "Unlocked", "3", "Enabled"),  # Tag 1
    ("Tag", "00 00 00 00 00 00 07 06 0a 00", "Empty", "Unlocked", "10", "Enabled"),  # Tag 1
    ("Tag", "00 00 00 00 00 00 07 06 1e 00", "Empty", "Unlocked", "30", "Enabled"),  # Tag 1
])
@pytest.mark.pethubcommand
def test_feeder_command_tagprovision(global_variables, request, operation, provhex, animal, lockstate, offset, tagstate):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 1000 127 11 00 01 00 b8 c8 42 54 " + provhex)
    assert result.Operation == 'Command'
    assert result.message[0].Operation == operation
    assert result.message[0].Operation == operation
    assert result.message[0].LockState == lockstate
    assert result.message[0].TagOffset == offset
    assert result.message[0].TagState == tagstate
    # if result.message[0].Operation == 'Tag' and result.message[0].Tag not in ['Empty']:
    #     assert result.message[0].Animal == animal
