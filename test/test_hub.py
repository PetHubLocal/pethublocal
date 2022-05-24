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


def setup_module():
    log.info('PyTest: Hub - Setup')
    pytest.hub = 'H010-0123456'
    pytest.mac = '6666666666666666'
    pytest.devtype = 6  # Device Type 6 = CatFlap


def teardown_module():
    log.info('PyTest: Hub - Teardown')
    with open('pethubconfig-updated.json', 'w') as fp:
        json.dump(pethubconfig, fp, indent=4)
    if TESTING_MQTT:
        mc.disconnect()
        log.info('PyTest: MQTT Disconnected')

# Hub Status
@pytest.mark.parametrize('operation, msg', [
    ("HubState", "Hub has gone offline (having been online since 17 10 3 14)"),
    ("HubState", "6137a868 0000 Hub online at 7 17 59 4"),
    ("Hub", "6137a868 0010 132 0 0 8 01 cd 00 02 00 2b 00 03"),
    ("Hub", "6137a868 0020 132 1 8 3 00 01 b1"),
    ("Hub", "6137a869 0030 132 2 13 3 00 00 00"),
    ("Hub", "6137a869 0040 132 3 18 1 00"),
    ("Hub", "6137a86a 0050 132 4 20 8 00 00 00 00 0f 00 00 00"),
    ("Hub", "6137a86a 0060 132 5 28 8 02 03 04 00 00 00 00 00"),
    ("Hub", "6137a86b 0070 132 6 36 8 00 00 00 00 00 00 00 0a"),
    ("Hub", "6137a86b 0080 132 7 44 8 04 33 33 33 33 33 33 33"),
    ("Hub", "6137a86c 0090 132 8 52 8 33 0d 00 00 00 12 34 56"),
    ("Hub", "6137a86c 00a0 132 9 60 8 78 44 44 44 44 44 44 44"),
    ("Hub", "6137a86d 00b0 132 10 68 8 44 11 00 00 00 12 34 56"),
    ("Hub", "6137a86d 00c0 132 11 76 8 78 66 66 66 66 66 66 66"),
    ("Hub", "6137a86d 00d0 132 12 84 8 66 19 00 00 00 12 34 56"),
    ("Hub", "6137a86e 00e0 132 13 92 8 78 88 88 88 88 88 88 88"),
    ("Hub", "6137a86e 00f0 132 14 100 8 88 21 00 00 00 12 34 56"),
    ("Hub", "6137a86f 0100 132 15 108 8 78 00 00 00 00 00 00 00"),
    ("Hub", "6137a86f 0110 132 16 116 8 00 fc ff ff ff ff ff ff"),
    ("Hub", "60b16017 0120 132 17 124 8 ff 00 00 00 00 00 00 00"),
    ("Hub", "60b16017 0130 132 18 132 8 00 fc ff ff ff ff ff ff"),
    ("Hub", "60b16018 0140 132 19 140 8 ff 00 00 00 00 00 00 00"),
    ("Hub", "60b16019 0150 132 20 148 8 00 fc ff ff ff ff ff ff"),
    ("Hub", "60b16019 0160 132 21 156 8 ff 00 00 00 00 00 00 00"),
    ("Hub", "60b1601a 0170 132 22 164 8 00 fc ff ff ff ff ff ff"),
    ("Hub", "60b1601a 0180 132 23 172 8 ff 00 00 00 00 00 00 00"),
    ("Hub", "60b1601b 0190 132 24 180 8 00 fc ff ff ff ff ff ff"),
    ("Hub", "60b1601b 01a0 132 25 188 8 ff 00 00 00 00 00 00 00"),
    ("Hub", "60b1601c 01b0 132 26 196 8 00 fc ff ff ff ff ff ff"),
    ("Hub", "60b1601c 01c0 132 27 204 1 ff"),
    ("Uptime", "61174ef6 0c90 10 00001320 14 05 04 54 61174ef6 1"),

    # ("6137a882 01d0 132 28 85 1 13"),
    # ("6137a886 01e0 132 29 69 1 23"),
    # ("6137a8a5 01f0 132 30 101 1 0f"),
    # ("6137a8b5 0200 132 31 102 1 03"),
    # ("6137a905 0220 132 33 71 5 18 8a 26 18 cf"),
    # ("6137a911 0230 132 34 53 1 1b"),
    # ("6137a91e 0260 132 36 87 5 29 c3 21 92 e7"),
    # ("6137a91e 0260 132 36 87 5 29 c3 21 92 e7"),

])
@pytest.mark.pethubcommand
def test_hub_registers(request, operation, msg):  # Hub Registers
    log.info('TEST: ' + request.node.name)
    response = run_test(request.node.name, pethubconfig, 'H010-0123456/messages', msg)
    if len(response) > 0:
        assert response.Operation == 'Status'
        assert response.message[0].Operation == operation
        # print('Hub Reg', pethubconfig['Devices']['H010-0123456']['Hub']['Registers'])


