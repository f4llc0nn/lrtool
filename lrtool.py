#!/usr/bin/env python3.10
# *******************************************************
# Copyright (c) 2022 Leone Tolesano (0xleone) - All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

from mergedeep import merge
import json, hashlib, random, base64, re, sys
import concurrent.futures
from threading import Lock
from cbc_sdk.helpers import build_cli_parser, get_cb_cloud_object
from cbc_sdk.platform import Device
from cbc_sdk import CBCloudAPI
from datetime import datetime, timedelta
FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

def flatten(nestedlist):
    """
    Sanitize nested lists if repeating args or same arg with multiple values separated by spaces:
    """
    flattened = []
    for l in nestedlist:
        if len(l) > 1:
            for i in l:
                flattened.append(i)
        else:
            flattened.append(l[0])
    return(flattened)

def sanitizeUpdateCfg(keyvalue):
    """
    Sanitize and validate prop=value trying to avoid invalid cfg.ini file:
    """
    config = keyvalue.split('=', 1)
    if len(config) > 1:
        match config[0]:
            case 'AmsiEnabled' | 'CBLR':
                return True if config[1] in ["false","true"] else False
            case 'AuthenticatedCLIUsers':
                #pattern = re.compile("^S-\d-\d+-(\d+-){1,14}\d+$")
                pattern = re.compile("^S-\d-(\d+-){1,14}\d+$")
                return True if pattern.match(config[1]) else False
            case 'ProxyServer' | 'ProxyServerCredentials': 
                pattern = re.compile("^\S+:\d{2,5}$")
                return True if pattern.match(config[1]) else False
            case _:
                return False
    else:
        return False

def sendLRCommands(api, device, commands, l, isDaemon=False, upd_cfg=False):
    lr_session = api.live_response.request_session(device.id)
    device_out = { device.id: { "live_response": {} } }
    count = 0

    if upd_cfg:
        count = 0
        for command in commands:
            lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True)
            count += 1
            if count == 8:
                cmd_output = lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True).decode('ascii')
                device_out[device.id]["live_response"]["config_update"] = True if "True" in cmd_output else False
                if not isDaemon:
                    l.acquire()
                    try:
                        cmd_return = "succeeded." if "True" in cmd_output else "has failed."
                        print(r'%s | %s | Config Update %s' % (device.id, device.name, cmd_return))
                    finally:
                        l.release()
    else:
        for command in commands:
            cmd_output = lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True)
            device_out[device.id]["live_response"][count] = { base64.b64encode(command.encode('ascii')).decode('ascii'): 
                base64.b64encode(cmd_output).decode('ascii')
            }
            count += 1
            if not isDaemon:
                l.acquire()
                try:
                    print(r'%s | %s | %s' % (device.id, device.name, command) +'\n'+cmd_output.decode('ascii'))
                finally:
                    l.release()
        
    lr_session.close()
    return device_out

def massLR(devicelist, commands, customprofile, isDaemon=False):
    now = datetime.utcnow()
    delta = timedelta(minutes=10)

    out = {}
    future_returns = []
    lock = Lock()
    platform_api = CBCloudAPI(profile=customprofile)
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
        for device in devicelist:
            out[device.id] = {}
            if now - datetime.strptime(device.last_contact_time, FORMAT) >= delta:
                out[device.id]["live_response"] = "OFFLINE"
            else:
                if not isinstance(commands, list):
                    backupfilename = r'cfg-bkp-%s.ini' %hashlib.md5(str(random.randrange(100000,999999)).encode()).hexdigest()
                    version = float(device.sensor_version.split(".")[0] + "." + d.sensor_version.split(".")[1])
                    cfgdir = r'C:\ProgramData\CarbonBlack\DataFiles' if version >= 3.6 else r'C:\Program Files\Confer'
                    prop = args.update_cfg
                    prop = prop.split('=')[0]
                    cmds = [
                        r'"C:\Program Files\Confer\repcli.exe" bypass 1',
                        r'cmd.exe /c copy %s\cfg.ini %s\%s' % (cfgdir, cfgdir, backupfilename),
                        r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -NotMatch | %% { $_.Line } > %s\cfg2.ini' % (cfgdir, prop, cfgdir),
                        r'cmd.exe /c move %s\cfg2.ini %s\cfg.ini' % (cfgdir, cfgdir),
                        r'powershell.exe Add-Content %s\cfg.ini "%s"' % (cfgdir, args.update_cfg),
                        r'"C:\Program Files\Confer\repcli.exe" updateconfig',
                        r'"C:\Program Files\Confer\repcli.exe" bypass 0',
                        r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -quiet' % (cfgdir, args.update_cfg)
                    ]
                    try:
                        future_returns.append(executor.submit(sendLRCommands,platform_api, device, cmds, lock, isDaemon, upd_cfg=True))
                    except:
                        out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"
                else:
                    try:
                        future_returns.append(executor.submit(sendLRCommands,platform_api, device, commands, lock, isDaemon))
                    except:
                        out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"

    for f in future_returns:
        out.update(f.result())
    return out

if __name__ == "__main__":
    parser = build_cli_parser("List devices")
    parser.add_argument("-n", "--hostname", help="Query string for looking for device names")
    parser.add_argument("-p", "--policy", action="append", help="Policy Name")
    parser.add_argument("-i", "--device_id", action='append', nargs='+', help="List of device_id's")
    parser.add_argument("-d", "--deployment_type", action="append", help="Deployment Type")
    parser.add_argument("-s", "--status", action="append", help="Status of device")
    # BROKEN:
    # parser.add_argument("-f", "--if_field", action='append', nargs='+', help="If field equals value. e.g. virtual_machine=true")
    parser.add_argument("-a", "--add_field", action='append', nargs='+', help="Add field(s) to output")
    parser.add_argument("-o", "--only_field", action='append', nargs='+', help="Choose the field(s) to output")
    parser.add_argument("-E", "--execute", action='append', nargs='+', help="Commands to execute on all filtered devices")
    parser.add_argument("-U", "--update_cfg", help="Update sensor config file")
    parser.add_argument("-J", "--daemon", action='store_true', help="Daemon mode. JSON output")

    args = parser.parse_args()
    cb = get_cb_cloud_object(args)
    devicelist = cb.select(Device)
    random.seed()
    output = {}

    # Filters:
    if args.hostname:
        devicelist = devicelist.where(args.hostname)
    if args.policy:
        devicelist = [d for d in devicelist if args.policy[0] in d.policy_name]
    if args.device_id:
        devicelist = [d for d in devicelist if str(d.id) in flatten(args.device_id)]
    if args.deployment_type:
        devicelist = devicelist.set_deployment_type(args.deployment_type)
    if args.status:
        devicelist = devicelist.set_status(args.status)
    ''' BROKEN:
    if args.if_field:
            filter = flatten(args.if_field)
            temp = []
            for fieldvalue in filter:
                field, value = fieldvalue.split("=")
                temp.append([d for d in devicelist if hasattr(d, field) and getattr(d, field) == value])
            devicelist = temp
    '''

    # Initiate JSON output:
    if devicelist:
        for d in devicelist:
            output[d.id] = {
                "device_id": d.id, 
                "device_name": d.name,
            }
            if not args.only_field:
                output[d.id].update({
                    "last_contact_time": d.last_contact_time,
                    "os": d.os, 
                    "os_version": d.os_version,
                    "sensor_version": d.sensor_version,
                    "policy_id": d.policy_id,
                    "policy_name": d.policy_name,
                    "current_sensor_policy_name": d.current_sensor_policy_name,
                    "mac_address": d.mac_address,
                    "last_internal_ip_address": d.last_internal_ip_address,
                    "last_external_ip_address": d.last_external_ip_address,
                    "scan_status": d.scan_status,
                    "passive_mode": d.passive_mode,
                    "quarantined": d.quarantined,
                    "vulnerability_score": d.vulnerability_score,
                    "vulnerability_severity": d.vulnerability_severity,
                    "deployment_type": d.deployment_type,
                    "uninstall_code": d.uninstall_code,
                })
    else:
        print(json.dumps({"device_count": 0, "results": None}, indent=2, sort_keys=False))
        sys.exit()

    # Presenters:
    if args.add_field or args.only_field:
        fields = flatten(args.add_field) if args.add_field else flatten(args.only_field)
        for d in devicelist:
            for field in fields:
                output[d.id].update({ field: getattr(d, field) }) if hasattr(d, field) else None

    # Executors:
    if args.execute or args.update_cfg:
        if args.execute:
            merge(output, massLR(devicelist, flatten(args.execute), args.profile, args.daemon).copy())
        if args.update_cfg and sanitizeUpdateCfg(args.update_cfg):
            merge(output, massLR(devicelist, args.update_cfg, args.profile, args.daemon).copy())

    # If not command-line execution or is Daemon, print JSON output:
    if args.daemon or (not args.execute and not args.update_cfg):
        if devicelist:
            print(json.dumps({"device_count": len(output), "results": output}, indent=2, sort_keys=False))
