"""
    Command line interface
    Copyright (c) 2022, Peter Lambrechtsen (peter@crypt.nz)
"""
import os
import sys
from os.path import dirname
sys.path.append(dirname(dirname(sys.path[0])))

import pethublocal.frontend as frontend
from pethublocal import log
from pethublocal.functions import config_load, config_save, download_firmware, download_credentials,\
    config_local, start_to_pethubconfig, config_defaults, parse_firmware_log
from pethublocal.generate import generatemessage

from pethublocal.consts import (
    SLEEPTIME,
    CONFIGFILE,
    CFG
)


from box import Box
import click
import json
from time import sleep


@click.group(invoke_without_command=True)
@click.pass_context
@click.help_option("-h", "--help")
def cli(ctx: click.Context) -> None:
    """
    PetHubLocal

    The local deployment for your SurePetCare Connect hub to Home Assistant
    """
    pass


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
@click.option("-sn", "--serialnumber", type=str, required=True, help="Hub Serial Number")
@click.option('-f', '--force', default=False, is_flag=True, help='Force Download')
def firmware(ctx: click.Context, serialnumber: str, force: bool) -> None:
    """ Download firmware for Hub from SureHub """
    log.info('Download Firmware Serial Number: ' + serialnumber)
    log.info(download_firmware(serialnumber, force))


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
@click.option("-sn", "--serialnumber", type=str, required=True, help="Hub Serial Number")
@click.option("-mac", "--macaddress", type=str, required=True, help="Hub Serial MAC Address")
def credentials(ctx: click.Context, serialnumber: str, macaddress: str) -> None:
    """ Download credentials for Hub from SureHub """
    log.info('Download Credentials Serial Number: %s MAC Address %s', serialnumber, macaddress)
    log.info(download_credentials(serialnumber, macaddress))


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
@click.option('-f', '--force', default=False, is_flag=True, help='Force refresh from SurePetCare cloud')
def setup(ctx: click.Context, force: bool) -> None:
    """ Build local configuration from SurePetCare Cloud """
    pethubconfig = config_load(True, force)
    config_save(pethubconfig)
    log.info('PetHubConfig config built: %s', json.dumps(pethubconfig))


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
@click.option("-sn", "--serialnumber", type=str, help="Hub Serial Number")
@click.option("-p", "--password", type=str, help="Password for Client Certificate if you have that")
def buildlocal(ctx: click.Context, password: str, serialnumber: str, force: bool) -> None:
    """ Build empty local configuration without cloud """
    log.info('Build local configuration - This assumes you already have either:')
    log.info('Client Certificate Password - https://pethublocal.github.io/certificate/')
    log.info('Or')
    log.info('Just going to build it using the hub serial number on first connect')
    log.info('Trust me... setup using the cloud as it is much easier :)')
    log.info('Build result ' + str(config_local(password=password, serialnumber=serialnumber)))


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
def start(ctx: click.Context) -> None:
    """ Start Pet Hub Local with existing pethublocal.json file """
    log.info('Start Pet Hub Local - Always blow on the pie, safer communities together')
    frontend.serve_pet_hub()
# @click.option("--nohttp", default=False, is_flag=True, help=f"Disable HTTP Server for Firmware Update and UI")
# @click.option("--nohttps", default=False, is_flag=True, help=f"Disable HTTPS Server for Hub Boot")
# @click.option("--nomqtt", default=False, is_flag=True, help=f"Disable MQTT Client parsing Hub and HA")


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
@click.option("-f", "--filename", type=str, required=True, help="Start file to parse")
def parsestart(ctx: click.Context, filename: str) -> None:
    """ Build configuration from SurePetCare Cloud """
    log.info('Build Config from %s', filename)
    if os.path.isfile(filename):
        log.info('Loading Config file %s', filename)
        start_file = Box.from_json(filename=filename)
        pethubconfig = start_to_pethubconfig(config_defaults(), start_file)
        config_save(pethubconfig)
        log.info(pethubconfig)


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
@click.option("-h", "--hub", type=str, required=True, help="Hub Serial Number")
@click.option("-d", "--device", type=str, required=True, help="Device Mac")
@click.option("-c", "--command", type=str, required=True, help="Command to send")
@click.option("-s", "--suboperation", type=str, help="Command to send")
def cmd(ctx: click.Context, hub: str, device: str, command: str, suboperation: str) -> None:
    """ Build configuration from SurePetCare Cloud """
    if os.path.isfile(CONFIGFILE):
        log.info('Loading Config file %s', CONFIGFILE)
        cfg = Box.from_json(filename=CONFIGFILE)
        product_id = cfg['Devices'][hub][device]['Product_Id']
        if device == 'Hub':
            message = generatemessage(cfg, hub, product_id, command)
        elif suboperation:
            message = generatemessage(cfg, hub, product_id, command, mac=device, suboperation=suboperation)
        else:
            message = generatemessage(cfg, hub, product_id, command, mac=device)
        print("mosquitto_pub -q 1 -t %s -m '%s'", next(iter(message)),next(iter(message.items()))[1])


@cli.command()
@click.pass_context
@click.help_option("-h", "--help")
@click.option("-f", "--filename", type=str, required=True, help="Log File from Firmware Update")
def parsefirmwarelog(ctx: click.Context, filename: str) -> None:
    """
     Parse firmware log file from the firmware update to find long_serial aka certificate password.
    """
    log.info('Parse Firmware Log')
    sn, password = parse_firmware_log(filename)
    print(sn, password)
    if len(password) == 32:
        log.info('Password Found: %s', password)
        answer = input(f'Update config {sn} with Password {password} ? Y/N')
        if len(answer) > 0 and answer[0].upper() == 'Y':
            print('Updating')


if __name__ == "__main__":
    # Main http web server for firmware downloading and the main frontend.
    cli()
