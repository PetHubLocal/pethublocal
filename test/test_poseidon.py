# Test Poseidon
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
    pytest.mac = '8888888888888888'
    pytest.devtype = 8               # Device Type 8 = Poseidon


def setup_module():
    log.info('setup')


def teardown_module():
    log.info('teardown')
    with open('pethubconfig-updated.json', 'w') as fp:
        json.dump(pethubconfig, fp, indent=4)


#Test Status Messages
@pytest.mark.pethubstatus
def test_poseidon_battery(global_variables, request):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "5fef6320 0050 126 18 0c 00 05 00 b8 c8 42 54 ae 17 00 00 d3 0c 00 00 25 01 00 00 0e 00 42 00")
    assert result.message[0].Operation == 'Battery'
    assert result.message[0].data.msg == '0c'
    assert result.message[0].data.counter == '5'
    assert result.message[0].Operation == 'Battery'
    assert result.message[0].Battery == "6.062"

@pytest.mark.parametrize("oplength, operation, action, time, fromval, to, delta, tagcount, tag", [
    ("1b", "02 00 00 01 48 ab 01 00 d8 bd ff ff 0a 00 24 01 00 00 00", "Removed", "0", "1093.84", "-169.36", "-1263.2", 0, ""),
    ("22", "01 0e 00 01 d8 bd ff ff d8 bd ff ff 0a 00 24 01 00 00 01 45 00 12 34 56 00 03", "Animaldrink", "14", "-169.36", "-169.36", "0.0", 1, "4500123456"),
    ("1b", "03 00 00 01 00 00 00 00 fa 64 01 00 0b 00 24 01 00 00 00", "Refilled", "0", "0.0", "913.86", "913.86", 0, ""),
    ("22", "01 3c 00 01 87 61 01 00 6c 5d 01 00 0b 00 24 01 00 00 01 14 cd 5b 07 00 e1 01", "Animaldrink", "60", "905.03", "894.52", "-10.51", 1, "900.000123456788"),
    ("29", "01 3c 00 01 87 61 01 00 6c 5d 01 00 0b 00 24 01 00 00 02 14 cd 5b 07 00 e1 01 15 cd 5b 07 00 e1 01", "Animaldrink", "60", "905.03", "894.52", "-10.51", 2, "900.000123456788"),
])
@pytest.mark.pethubcommand
def test_poseidon_drinking(global_variables, request, oplength, operation, action, time, fromval, to, delta, tagcount, tag):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac, "610d8c83 0010 126 " + oplength + " 1b 00 01 00 b8 c8 42 54 " + operation)
    assert result.Operation == 'Status'
    assert result.message[0].Operation == "Drinking"
    assert result.message[0].Action == action
    assert result.message[0].Time == time
    assert result.message[0].From == fromval
    assert result.message[0].To == to
    assert result.message[0].Delta == [delta]
    assert result.message[0].TagCount == tagcount
    if tagcount > 0:
        assert result.message[0].Tag[0] == tag


@pytest.mark.parametrize("test_generate,genvalue,genresponse", [
    ("AddTag", 1, " 0f 01 00 00 00"),      # Set Left Target Weight
])
@pytest.mark.pethubcommand
def test_poseidon_command_updatestate(global_variables, request, test_generate, genvalue, genresponse):
    result = run_test(request.node.name, pethubconfig, pytest.hub + '/messages/' + pytest.mac,"5fef6320 1000 127 09 00 12 01 b8 c8 42 54" + genresponse)
    assert result.Operation == 'Command'
    assert result.message[0].data.msg == '09'
    assert result.message[0].data.counter == '274'
    assert result.message[0].Operation == 'UpdateState'
    assert result.message[0].SubOperation == test_generate
    assert result.message[0].State == genvalue
    assert result.message[0].Operation == 'UpdateState'
