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


@pytest.mark.parametrize("test_query, response", [
    ("DumpRegisters", "3 0 630"),
    ("GetBattery", "3 30 10"),
    ("GetProv", "3 59 2"),
    ("GetSlot", "3 60 1"),
    ("GetTag", "3 91 35"),
    ("GetCurfew", "3 519 6"),
    ("Unlocked", "2 36 1 00"),
    ("KeepIn", "2 36 1 01"),
    ("KeepOut", "2 36 1 02"),
    ("Locked", "2 36 1 03"),
    ("Curfew", "2 36 1 04"),
    ("LockState39", "2 39 1 01"),
])
@pytest.mark.pethubcommand
def test_generate_petdoor_cmd(global_variables, request, test_query, response):
    """ General commands """
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, test_query, mac=pytest.mac)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message


def test_generate_petdoor_time(global_variables, request):
    """ Set Time """
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, 'SetTime', mac=pytest.mac)
    now = p.datetime.now()  # Current timestamp in local time
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert f' 1000 2 34 2 {now.hour:02x} {now.minute:02x}' in message


@pytest.mark.parametrize("test_query, response", [
    ('Disabled', '3 00 00 00'),
    ('NonSelective', '3 00 00 01'),
    ('Rechargeables', '3 00 00 02'),
    ('ThreeSeconds', '3 00 00 04'),
    ('TenSeconds', '3 00 00 08'),
    ('Intruder', '3 00 00 10'),
    ('OppositeCurfew', '3 00 00 20'),
    ('ExtendedRange', '3 00 02 00'),
])
@pytest.mark.pethubcommand
def test_generate_petdoor_custom_mode(global_variables, request, test_query, response):
    """ Custom Modes """
    log.info('TEST: ' + request.node.name)
    pethubconfig['Devices'][pytest.hub][pytest.mac]['Custom_Mode'] = 0
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, 'CustomMode', mac=pytest.mac, suboperation=test_query)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message


@pytest.mark.parametrize("curfews, curfewenabled, response", [
    ("02:22-03:33", True, "02 02 16 03 21 00"),
    ("12:34-05:55", False, "01 0c 22 05 37 00"),
])
@pytest.mark.pethubcommand
def test_generate_petdoor_cmd(global_variables, request, curfews, curfewenabled, response):
    """ General commands """
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, 'CURFEWS', mac=pytest.mac, curfews=curfews, curfewenabled=curfewenabled)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message


@pytest.mark.parametrize("operation,offset,tag,response", [
    ("TagProvision", "1", "900.000123456790", " 98 7 01 68 b3 da e0 00 87"),
    ("TagProvision", "2", "900.000123456791", " 105 7 01 e8 b3 da e0 00 87"),
    ("TagProvision", "3", "900.000123456792", " 112 7 01 18 b3 da e0 00 87"),
    ("TagProvision", "4", "900.000123456793", " 119 7 01 98 b3 da e0 00 87"),
])
@pytest.mark.pethubgenerate
def test_catflap_generate_setvalues(global_variables, request, operation, offset, tag, response):
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, operation, mac=pytest.mac, offset=offset, tag=tag)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message
        # assert ' 1000 127 11 00 ' in message  # Tag Provision and Lock State is 11



    # "CurfewState":   {"msg": "2 519 6 SS FF FF TT TT 00",  "desc": "Set Curfew time From / To"},             # Enable curfew time from database