#!/usr/bin/env python3
"""
   Pet Hub Local frontend for serving http, https and mqtt message translation
   Copyright (c) 2022, Peter Lambrechtsen (peter@crypt.nz)
"""

import calendar
import os
import sys
import platform
import asyncio
import ssl
import urllib.parse
from asyncio import sleep
from box import Box
from datetime import datetime, timezone, timedelta
from contextlib import AsyncExitStack, asynccontextmanager
from asyncio_mqtt import Client, MqttError
from multidict import MultiDict
from aiohttp import web
import socketio
import json
import os

from pethublocal.enums import PetDoorDirection


from .functions import config_load, config_save, download_credentials, download_firmware, \
    parse_mqtt_message, ha_init_entities, ha_update_state, json_print, update_watchdog, get_watchdog
from .generate import generatemessage
from . import log
from .consts import (
    LOGNAME,
    PH_HUB_T,
    PH_HA_T,
    SUREHUBHOST,
    LOGLEVEL,
    CFG,
    DEV,
    REINITDAYS,
    MQTTSLEEP,
    FIRMWAREVERSION
)
from importlib.resources import files

import logging
from logging.handlers import TimedRotatingFileHandler
logging.basicConfig(
    level=LOGLEVEL,
)

sio = socketio.AsyncServer(async_mode='aiohttp', async_handlers=True)


async def credentials(request):
    """
     Serve credentials api request from hub
     Hub post body:
     serial_number=H0xx-0xxxxxx&mac_address=0000xxxxxxxxxxxx&product_id=1&firmware_version=2.43
    """
    utctime = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %Z")
    body = urllib.parse.parse_qs(await request.text())
    serial_number = body['serial_number'][0]
    mac_address = body['mac_address'][0]
    firmware_version = body['firmware_version'][0]
    log.info('Hub Request ' + await request.text())
    # Set Default Values
    payload = ['v02', '', '', '', '', '1', '', SUREHUBHOST, '']
    payload[1] = str(int(serial_number.split('-')[1]))
    payload[2] = serial_number  # MQTT Client Username
    config = request.app['pethubconfig'][CFG]['MQTT']
    if 'HubUsername' in config:
        payload[3] = config['HubUsername']
    if 'HubPassword' in config:
        payload[4] = config['HubPassword']
    payload[6] = PH_HUB_T + serial_number  # MQTT Topic for Hub including serial number
    # Overwrite the MQTT Host for the hub if it is different from the current host, otherwise
    # point to the default value of hub.api.surehub.io which is the DNS poisoned current host
    if 'Host' in config and '127.0.0.1' not in config.Host:
        payload[7] = config['Host']
    download_creds = False
    firmware_update = False
    devices = request.app['pethubconfig']['Devices']
    hub = Box({})
    if serial_number in devices:
        hub = devices[serial_number]['Hub']
        # Check if we have client cert
        if 'Client_Cert' in hub:
            payload[8] = hub['Client_Cert']
        else:
            download_creds = True
        # If you want to force a firmware update, add the X-Update = 1 header
        if 'Firmware_Update' in hub and hub['Firmware_Update']:
            firmware_update = True
    else:
        download_creds = True
    if download_creds:  # **TODO Fixup Cred Download
        mac_address = body['mac_address'][0]
        creds = download_credentials(hub, serial_number, mac_address, firmware_version).split(':')
        log.info('Download Creds: %s', ':'.join(creds))
        hub['Client_Cert'] = creds[8]
        payload[8] = creds[8]
    response_body = ':'.join(payload)
    log.info('Hub Credentials Response ' + response_body)
    headers = MultiDict({'Date': utctime,
                         'Content-Type': 'text/html; charset=utf-8',
                         'Content-Length': str(len(response_body)),
                         'Connection': 'keep-alive',
                         'server': 'nginx'})
    if firmware_update:  # Force Firmware Update on Hub
        headers.add('X-Update', '1')
    return web.Response(headers=headers, text=response_body)


async def https_app(pet_hub_config):
    """ HTTP Server for credentials request from hub """
    log.info("Starting HTTPS Server")
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    config = pet_hub_config[CFG]
    cert = config['Web']['Cert']
    cert_key = config['Web']['CertKey']
    if not os.path.isfile(cert):
        package_dir = files("pethublocal") / "static"
        cert = str(package_dir / cert)
        cert_key = str(package_dir / cert_key)
    ssl_context.load_cert_chain(cert, cert_key)
    app_s = web.Application()
    app_s['pethubconfig'] = pet_hub_config
    # Add route over HTTPS for hub retrieving credentials
    app_s.add_routes([web.post('/api/credentials', credentials)])
    runner = web.AppRunner(app_s, access_log_format='%a "%r" %s %b "%{Referer}i" "%{User-Agent}i"',)
    await runner.setup()
    site = web.TCPSite(runner, config['Web']['Host'], port=config['Web']['HTTPSPort'], ssl_context=ssl_context)
    await site.start()


async def firmware(request):
    """
     Serve firmware request from hub
     Post body:
     serial_number=H0xx-0xxxxxx&page=xx&bootloader_version=1.177
    """
    utctime = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %Z")
    request_body = await request.text()
    log.info('HTTP: Firmware hub request %s', request_body)
    body_dict = urllib.parse.parse_qs(request_body)
    serial_number = body_dict['serial_number'][0]
    page = body_dict['page'][0]
    bootloader_version = body_dict['bootloader_version'][0]
    customfirmware = f'{serial_number}-{FIRMWAREVERSION}-{page.zfill(2)}.bin'
    standardfirmware = f'{serial_number}-{bootloader_version}-{page.zfill(2)}.bin'
    if os.path.isfile(customfirmware):
        filename = customfirmware
    elif os.path.isfile(standardfirmware):
        filename = standardfirmware
    else:
        # Download hub firmware if it doesn't exist locally from Surepet
        log.info('Firmware Missing, need to download it')
        # log.info('HTTP: Local firmware does not exist, downloading from Surepet')
        # force_download = False
        # if int(page) > 0:  # Force download if page is >0 and file doesn't exist
        #     force_download = True
        #     log.info('HTTP: Download firmware from surepet for %s ', serial_number)
        # # download_firmware(serial_number, force_download)

    log.info('HTTP: Firmware image file %s', filename)

    # Check if firmware update flag is enabled, and disable it during firmware update
    devices = request.app['pethubconfig']['Devices']
    if serial_number in devices:
        hub = devices[serial_number]['Hub']
        if 'Firmware_Update' in hub and hub['Firmware_Update']:
            config = request.app['pethubconfig']
            config['devices'][serial_number]['Hub']['Firmware_Update'] = False
            request.app['pethubconfig'] = config
            config_save(config)
    # Serve firmware
    response = web.Response(text='')
    if os.path.isfile(filename):
        with open(filename, 'rb') as firmware_file:
            firmware_image = firmware_file.read()
            headers = MultiDict({'Date': utctime,
                                 'Content-Type': 'text/html; charset=utf-8',
                                 'Cache-Control': 'no-cache, private',
                                 'Content-Length': str(len(firmware_image)),
                                 'Connection': 'keep-alive',
                                 'Server': 'nginx'})
            response = web.Response(headers=headers, body=firmware_image)
    else:
        log.info('HTTP: Firmware missing %s page %s', serial_number, page)
    return response


async def pethubconfig(request):
    """ Return pethubconfig """
    return web.Response(content_type='application/javascript', body='pethubconfig=JSON.parse(\'' + json.dumps(request.app['pethubconfig']) + '\');')


async def start_tasks(app):
    loop = asyncio.get_event_loop()
    loop.create_task(mqtt_start(app))
    loop.create_task(https_app(app['pethubconfig']))
    loop.create_task(hub_watchdog(app))
    loop.create_task(clear_lookedin_state(app))


async def mqtt_start(app):
    reconnect_interval = 3  # [seconds]
    while True:
        try:
            async with AsyncExitStack() as stack:
                tasks = set()
                stack.push_async_callback(cancel_tasks, tasks)
                if 'Host' in app['pethubconfig'][CFG]['MQTT']:
                    mqtt_host = app['pethubconfig'][CFG]['MQTT']['Host']
                    log.info('MQTT: Init MQTT Host %s', mqtt_host)
                    mqtt_config = {
                        'hostname': mqtt_host,
                        'port': 1883,
                        'client_id': 'PetHubLocal'
                    }
                    # Add Client Username / Password if it is in pethubconfig
                    if any(x in app['pethubconfig'][CFG]['MQTT'] for x in ['ClientUsername', 'ClientPassword']):
                        mqtt_config['username'] = app['pethubconfig'][CFG]['MQTT']['ClientUsername']
                        mqtt_config['password'] = app['pethubconfig'][CFG]['MQTT']['ClientPassword']
                    if 'ClientPort' in app['pethubconfig'][CFG]['MQTT']:
                        mqtt_config['port'] = app['pethubconfig'][CFG]['MQTT']['ClientPort']
                        if mqtt_config['port'] == 8883:
                            mqtt_config['tls_context'] = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    client = Client(**mqtt_config)
                    app['mqtt_client'] = client
                else:
                    log.info('MQTT Host missing from config')
                    sys.exit(1)

                await stack.enter_async_context(client)

                # Initialise Home Assistant Topics
                if 'Last_HA_Init' in app['pethubconfig'][CFG]:
                    last_ha_init = app['pethubconfig'][CFG]['Last_HA_Init']
                    last_update = datetime.utcfromtimestamp(last_ha_init)
                    log.debug('HAInit - Last Init Time: %s', str(last_ha_init))
                    log.info('MQTT: Initialise Home Assistant entities')
                    if (datetime.utcnow() - last_update > timedelta(days=REINITDAYS)):
                        # Re-Init HA MQTT Discovery entities
                        ha_init = ha_init_entities(app['pethubconfig'])
                        for topic, message in ha_init.items():
                            log.debug('HA_INIT: Topic:%s Message:%s', topic, message)
                            await client.publish(topic, message, qos=0, retain=True)
                            await sleep(MQTTSLEEP)  # Sleep as HA doesn't like getting a lot of messages at once
                        # Re-init States
                        ha_init_state = ha_update_state(app['pethubconfig'])
                        for topic, message in ha_init_state.items():
                            log.debug('HA_INIT: Pet Topic:%s Message:%s', topic, message)
                            await client.publish(topic, message, qos=0, retain=True)
                            await sleep(MQTTSLEEP)  # Sleep as HA doesn't like getting a lot of messages at once
                        app['pethubconfig'][CFG]['Last_HA_Init'] = calendar.timegm(datetime.utcnow().timetuple())

                # Query Hub Devices for current Time and Battery State on startup
                if 'Get_State' in app['pethubconfig'][CFG]:
                    update_messages = ['SETTIME', 'GETBATTERY']
                    for hub, devices in app['pethubconfig'][DEV].items():
                        for device, values in devices.items():
                            if 'Last_Device_Update' in values:
                                last_update = datetime.utcfromtimestamp(values['Last_Device_Update'])
                                if (datetime.utcnow() - last_update > timedelta(days=1)):
                                    for update in update_messages:
                                        topic = list(generatemessage(app['pethubconfig'], hub,
                                                            values.Product_Id, update, mac=values['Mac_Address']).items())[0]
                                        await client.publish(topic[0],topic[1], qos=1, retain=False)
                                        await sleep(MQTTSLEEP)  # Sleep as HA doesn't like getting a lot of messages at once
                                    app['pethubconfig'][DEV][hub][device]['Last_Device_Update'] = calendar.timegm(datetime.utcnow().timetuple())

                config_save(app['pethubconfig'])

                # Topics to filter to messages
                topic_filters = [
                    f'{PH_HUB_T}+/messages/+',
                    f'{PH_HUB_T}+/messages',
                    f'{PH_HA_T}+/KeepIn',
                    f'{PH_HA_T}+/KeepOut',
                    f'{PH_HA_T}+/Curfew',
                    'v2/production/+/messages/+',  # The cloud topics
                    'v2/production/+/messages'
                ]

                for topic_filter in topic_filters:
                    log.info('MQTT: Topic filter: %s', topic_filter)
                    manager = client.filtered_messages(topic_filter)
                    messages = await stack.enter_async_context(manager)
                    task = asyncio.create_task(parse_message(client, app, messages))
                    tasks.add(task)
                await client.subscribe("#")

                # Add Socket.IO MQTT Client
                task = asyncio.create_task(queue_mqtt(client, app))
                tasks.add(task)

                await asyncio.gather(*tasks)

        except MqttError as error:
            log.info(f'Error "{error}". Reconnecting in {reconnect_interval} seconds.')
        finally:
            await asyncio.sleep(reconnect_interval)


async def hub_watchdog(app):
    check_interval = 60  # [seconds]
    log_count = 10
    update_watchdog()		# Init Watchdog timestamp
    while True:
      seconds = get_watchdog()
      minutes = seconds / 60
      log_count += 1
      if log_count >= 5:
        log.debug('Watchdog status - Last Hub message was %d seconds (%d minutes) ago',seconds,minutes)
        log_count = 0
      if minutes >= 70 :
        os.system("systemctl stop mosquitto && rm -f /var/lib/mosquitto/mosquitto.db && systemctl start mosquitto")
        log.info('Hub watchdog triggered, no message since %d minutes! Restarted mosquitto and deleted persistent data',minutes)
        update_watchdog()		# Reload Watchdog timer with current time
      await asyncio.sleep(check_interval)


# Monitor the LookedIn state of pets
# If a pet is in the LookedIn state for more than 20 seconds, reset it to Outside
# This helps to ensure that Home Assistant gets nice updates each time they look in.
async def clear_lookedin_state(app):
    check_interval = 10  # [seconds]
    state_expiration = 30 # [seconds]
    client = app.get('mqtt_client')

    while True:
        should_update_ha = False
        pets = app['pethubconfig'].get('Pets', [])
        for pet_id, pet in pets.items():
            activity = pet.get('Activity', {})
            where = activity.get('Where')
            time_str = activity.get('Time')
            if where == PetDoorDirection.Outside_LookedIn.name and time_str:
                try:
                    activity_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    now = datetime.now(timezone.utc)
                    elapsed = (now - activity_time.replace(tzinfo=timezone.utc)).total_seconds()
                    if elapsed > state_expiration:
                        log.info(f"Pet {pet_id} has been in LookedIn state for {elapsed} seconds, resetting to Outside")
                        activity['Where'] = PetDoorDirection.Outside.name
                        activity['Time'] = now.strftime("%Y-%m-%d %H:%M:%S")
                        activity['Update_Mac'] = "PetHubLocal"
                        pet['Activity'] = activity
                        should_update_ha = True
                except Exception as e:
                    log.warning(f"Could not parse activity time '{time_str}': {e}")

        config_save(app['pethubconfig'])

        if should_update_ha:
            log.info("Updating Home Assistant with cleared LookedIn states")
            if client:
                ha_init_state = ha_update_state(app['pethubconfig'])
                for topic, message in ha_init_state.items():
                    log.debug('HA_INIT: Pet Topic:%s Message:%s', topic, message)
                    await client.publish(topic, message, qos=0, retain=True)
                    await sleep(MQTTSLEEP)  # Sleep as HA doesn't like getting a lot of messages at once
                app['pethubconfig'][CFG]['Last_HA_Init'] = calendar.timegm(datetime.utcnow().timetuple())
            else:
                log.warning("MQTT client not available, cannot update Home Assistant")
        
        await asyncio.sleep(check_interval)


async def queue_mqtt(client, app):
    log.info("Client: Start")
    client_sio = socketio.AsyncClient()

    @client_sio.event
    async def connect():
        log.info('Client: Connected')

    @client_sio.on('queue_message')
    async def queue_message(data):
        log.debug('Client: received with %s', data)
        # if
        await client.publish('pethub/output', data, qos=0, retain=False)

    http_port = app['pethubconfig'][CFG]['Web']['HTTPPort']
    await client_sio.connect('http://127.0.0.1:' + str(http_port))
    log.info("Client: SID %s",client_sio.sid)
    await client_sio.wait()


async def parse_message(client, app, messages):
    async for message in messages:
        if message.topic.startswith(PH_HUB_T) or message.topic.startswith(PH_HA_T):
            parsed_result = parse_mqtt_message(app['pethubconfig'], message.topic, message.payload.decode())
            await sio.emit('web_message', data=parsed_result)
            if 'HubMessage' in parsed_result:
                log.debug('ToHub: Parsed Message %s', parsed_result['HubMessage'])
                for hub_message in parsed_result['HubMessage']:
                    for key, value in hub_message.items():
                        await client.publish(key, value, qos=1, retain=False)
            if 'HAMessage' in parsed_result:
                log.debug('ToHA: Parsed Message %s', parsed_result['HAMessage'])
                for key, value in parsed_result['HAMessage'].items():
                    await client.publish(key, value, qos=0, retain=True)
            if 'Save_Config' in parsed_result and parsed_result['Save_Config']:
                config_save(app['pethubconfig'])

        if message.topic.startswith('pethub/in'):
            print('emit message', message.payload.decode())


async def cancel_tasks(tasks):
    """ Cancel tasks """
    for task in tasks:
        if task.done():
            continue
        try:
            task.cancel()
            await task
        except asyncio.CancelledError:
            pass


async def root_handler(request):
    """ Default index.html handler """
    return web.HTTPFound('/index.html')


def log_renamer(log_name):
    base_filename, ext, date = log_name.split(".")
    return f"{base_filename}.{date}.{ext}"


@sio.on('connect')
async def connect(sid, environ):
    log.info("SIO: Connect %s", sid)


@sio.on('disconnect')
async def disconnect(sid):
    log.info('SIO: Disconnect %s', sid)


@sio.on('browser_message')
async def browser_message(sid, data):
    log.info('SIO: browser_message %s', data)
    await sio.emit('queue_message', data)


def serve_pet_hub():
    """ Main Pet Hub Webserver and MQTT Client """
    log.info('Serve: Starting Server')
    # Change to the "Selector" event loop for Windows
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    config = config_load()  # Load config

    # Start application, attach Socket IO, and routes
    app = web.Application()
    logging.basicConfig(
        level=LOGLEVEL,
    )

    sio.attach(app)
    app['pethubconfig'] = config
    app.router.add_post('/api/firmware', firmware)
    app.router.add_get('/pethubconfig', pethubconfig)
    app.router.add_route('*', '/', root_handler)
    app.router.add_static('/', str(files("pethublocal") / "static"))
    app.on_startup.append(start_tasks)
    log.info("Starting HTTP Server")
    web.run_app(
        app,
        access_log_format='%a "%r" %s %b "%{Referer}i" "%{User-Agent}i"',
        host=config[CFG]['Web']['Host'],
        port=config[CFG]['Web']['HTTPPort'])


if __name__ == "__main__":
    serve_pet_hub()
