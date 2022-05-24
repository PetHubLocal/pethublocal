# Test Feeder
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
        config_save(pethubconfig)
    return result


@pytest.fixture
def global_variables():
    pytest.hub = 'H010-0123456'
    pytest.devtype = 1               # Device Type 1 = Hub


def setup_module():
    log.info('setup')


def teardown_module():
    log.info('teardown')


# Generate Messages
@pytest.mark.parametrize("test_generate, response", [
    ("DumpRegisters", "3 0 205"),
    ("Adopt", "2 15 1 02"),
    ("AdoptDisable", "2 15 1 00"),
    ("AdoptButton", "2 15 1 82"),
    ("EarsOff", "2 18 1 00"),
    ("EarsOn", "2 18 1 01"),
    ("EarsDimmed", "2 18 1 04"),
    ("FlashEarsOff", "2 18 1 80"),
    ("FlashEarsOn", "2 18 1 81"),
    ("FlashEarsDim", "2 18 1 84"),
])
@pytest.mark.pethubgenerate
def test_hub_generate(global_variables, request, test_generate, response):
    log.info('TEST: ' + request.node.name)
    result = g.generatemessage(pethubconfig, pytest.hub, pytest.devtype, test_generate)
    log.info(json_print(result))
    for topic, message in result.items():
        assert topic == hub + pytest.hub + '/messages'
        assert response in message
