# Test Pet Hub Local
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
    pytest.mac = '6666666666666666'
    pytest.devtype = 6               # Device Type 6 = CatFlap


def setup_module():
    log.info('setup')


def teardown_module():
    log.info('teardown')
    with open('pethubconfig-updated.json', 'w') as fp:
        json.dump(pethubconfig, fp, indent=4)


# Generate Messages
@pytest.mark.parametrize("test_generate, response", [
    ("Time", "07 00 00"),         # Ack Time
    ("Config", "09 00 00"),       # Boot message 09
    ("Boot10", "10 00 00"),       # Boot message 10
    ("Tags", "11 00 00"),         # Tag provisioning
    ("Curfew", "12 00 00"),       # Curfew
    ("PetMovement", "13 00 00"),  # Pet movement in / out cat flap
    ("Boot17", "17 00 00"),       # Boot message 17
    ("Unknown0b", "0b 00 00"),    # Unknown 0b message
    ("Battery", "0c 00 00"),      # Battery state change
])
@pytest.mark.pethubgenerate
def test_catflap_generate_ack(global_variables, request, test_generate, response):
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, 'Ack', mac=pytest.mac, suboperation=test_generate)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message
        assert ' 1000 127 00 00 ' in message  # Ack message is type '00'


@pytest.mark.parametrize("test_generate,response", [
    ("Boot9", "09 00 ff"),    # Boot message 09
    ("Boot10", "10 00"),      # Boot message 10
    ("Tags", "11 00 ff"),     # Tag provisioning
    ("Boot17", "17 00 00"),   # Boot message 17
    ("Unknown0b", "0b 00"),   # Unknown 0b message
    ("Battery", "0c 00"),     # Battery state change
])
@pytest.mark.pethubgenerate
def test_catflap_generate_get(global_variables, request, test_generate, response):
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, 'Get', mac=pytest.mac, suboperation=test_generate)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message
        assert ' 1000 127 01 00 ' in message  # Get message is type '01'


@pytest.mark.pethubgenerate
def test_catflap_generate_settime(global_variables, request):
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, 'SetTime', mac=pytest.mac)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert ' 1000 127 07 00 ' in message
        assert ' 00 00 00 00 07' in message


@pytest.mark.parametrize("test_generate,response", [
    # ("08:30-10:00,11:30-20:00,12:30-21:00,14:30-22:00", "80 37 97 56 00 50 97 56 03 80 67 97 56 00 70 98 56 03 80 77 97 56 00 80 98 56 03 80 17 98 56 00 90 98 56 03"),        # Set all curfews
    ("", "00 00 42 00 00 00 42 00 06 00 00 42 00 00 00 42 00 06 00 00 42 00 00 00 42 00 06 00 00 42 00 00 00 42 00 06"),
])
def test_catflap_generate_catflapcurfew(global_variables, request, test_generate, response):
    log.info('TEST: ' + request.node.name)
    # result = g.generatemessage(mac="6666666666666666", devtype=6, counter=20, operation="Curfew", suboperation="08:30-10:00,11:30-20:00,12:30-21:00,14:30-22:00")
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, 'Curfews', mac=pytest.mac, suboperation=test_generate)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message
        assert ' 1000 127 12 00 ' in message  # Curfew is 12


@pytest.mark.parametrize("test_generate,offset,tag,lockstate,tagstate,response", [
    ("KeepIn",      "", "", "", "", " 00 00 00 00 00 00 07 03 00 02"),
    ("Locked",      "", "", "", "", " 00 00 00 00 00 00 07 04 00 02"),
    ("KeepOut",     "", "", "", "", " 00 00 00 00 00 00 07 05 00 02"),
    ("Unlocked",    "", "", "", "", " 00 00 00 00 00 00 07 06 00 02"),
    ("TagProvision", "1", "900.000123456790", "Normal", "Enabled", " 16 cd 5b 07 00 e1 01 02 01 00"),
    ("TagProvision", "2", "900.000123456791", "KeepIn", "Enabled", " 17 cd 5b 07 00 e1 01 03 02 00"),
    ("TagProvision", "3", "900.000123456792", "Normal", "Disabled", " 18 cd 5b 07 00 e1 01 02 03 01"),
    ("TagProvision", "4", "900.000123456793", "KeepIn", "Disabled", " 19 cd 5b 07 00 e1 01 03 04 01"),
])
@pytest.mark.pethubgenerate
def test_catflap_generate_setvalues(global_variables, request, test_generate, offset, tag, lockstate, tagstate, response):
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, test_generate, mac=pytest.mac, offset=offset, tag=tag, lockstate=lockstate, tagstate=tagstate)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages/' + pytest.mac
        assert response in message
        assert ' 1000 127 11 00 ' in message  # Tag Provision and Lock State is 11
