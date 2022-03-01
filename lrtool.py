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

def sanitizeValue(value):
    try:
        return float(value)
    except ValueError:
        match value.lower():
            case 'true':
                return True
            case 'false':
                return False
            case _:
                return value

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
                pattern = re.compile("^S-\d-(\d+-){1,14}\d+$")
                return True if pattern.match(config[1]) else False
            case 'ProxyServer' | 'ProxyServerCredentials': 
                pattern = re.compile("^\S+:\d{2,5}$")
                return True if pattern.match(config[1]) else False
            case _:
                return False
    else:
        return False

def executeLR(api, device, commands, wait=True, isDaemon=False):
    with api.live_response.request_session(device.id) as lr_session:
        device_out = { device.id: { "live_response": {} } }
        count = 0
        for command in commands:
            cmd_output = lr_session.create_process(r'%s' %command, wait_for_output=wait, wait_for_completion=wait)
            if wait:
                device_out[device.id]["live_response"][count] = { 
                    base64.b64encode(command.encode('ascii')).decode('ascii'): base64.b64encode(cmd_output).decode('ascii')
                }
            else:
                device_out[device.id]["live_response"][count] = { 
                    base64.b64encode(command.encode('ascii')).decode('ascii'): "RUNNING_ON_BACKGROUND"
                }
            count += 1
            if not isDaemon:
                if wait:
                    print(r'%s|%s ❯ %s' % (device.id, device.name, command) +'\n'+cmd_output.decode('ascii'))
                else:
                    print(r'%s|%s ❯ "%s": %s' % (device.id, device.name, command, "RUNNING_ON_BACKGROUND"))
        lr_session.close()
    if device_out:
        return device_out
    else:
        return { device.id: { "live_response": "CONN_FAILED_OR_TIMEOUT" } }
    
def massExecuteLR(devicelist, commands, wait=True, isDaemon=False, workers=80, customprofile="default"):
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        counter = 0
        api = CBCloudAPI(profile=customprofile)
        for device in devicelist:
            out[device.id] = {}
            try:
                futures.append(executor.submit(executeLR, api, device, commands, wait, isDaemon))
                counter += 1
            except:
                out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"

    for f in concurrent.futures.as_completed(futures, timeout=10):
        if f.exception() is None:
            out.update(f.result())
        else:
            out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"
    return out

def findAndKillLR(api, device, pnamelist, killIt=False, isDaemon=False):
    out = { device.id: { "live_response": {"find_processes": {} } } }
    with api.live_response.request_session(device.id) as lr_session:
        match_processes = []
        running_processes = lr_session.list_processes()
        for pname in pnamelist:
            out[device.id]["live_response"]["find_processes"][pname] = {"status": "NOT_FOUND", "matches_count": 0, "matches_pid": [], "matches_details": {} }
            match = False
            for process in running_processes:
                if ((pname.lower() in (process["process_path"]).lower()) or (pname.lower() in (process["process_cmdline"]).lower())):
                    match = True
                    match_processes.append(process["process_pid"])
                    out[device.id]["live_response"]["find_processes"][pname]["status"] = "KILLED" if killIt else "FOUND"
                    out[device.id]["live_response"]["find_processes"][pname]["matches_count"] += 1
                    out[device.id]["live_response"]["find_processes"][pname]["matches_pid"].append(process["process_pid"])
                    out[device.id]["live_response"]["find_processes"][pname]["matches_details"][process["process_pid"]] = process
                    if not isDaemon:
                        print(r'%s|%s ❯ %s: %s (PID: %s)' % (device.id, device.name, "\""+pname+"\"", out[device.id]["live_response"]["find_processes"][pname]["status"], process["process_pid"]))
            if not match and not isDaemon:
                print(r'%s|%s ❯ %s: %s' % (device.id, device.name, "\""+pname+"\"", out[device.id]["live_response"]["find_processes"][pname]["status"]))

        if killIt and len(match_processes) > 0:
            for pid in match_processes:
                lr_session.kill_process(pid)
        lr_session.close()
    return out

def massFindAndKillLR(devicelist, pnamelist, kill=False, isDaemon=False, workers=80, customprofile="default"):
    out = {}
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        api = CBCloudAPI(profile=customprofile)
        for device in devicelist:
            out[device.id] = {}
            try:
                futures.append(executor.submit(findAndKillLR, api, device, pnamelist, killIt=kill, isDaemon=isDaemon))
            except:
                out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"

    for f in concurrent.futures.as_completed(futures, timeout=20):
        if f.exception() is None:
            out.update(f.result())
        else:
            out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"
    return out


def updateConfigFile(api, device, commands, isDaemon=False):
    device_out = { device.id: { "live_response": {} } }
    device_out[device.id]["live_response"]["config_update"] = False
    with api.live_response.request_session(device.id) as lr_session:
        count = 0
        for command in commands:
            lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True)
            count += 1
            if count == 8:
                cmd_output = lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True).decode('ascii')
                device_out[device.id]["live_response"]["config_update"] = True if "True" in cmd_output else False
                if not isDaemon:
                    cmd_return = "Success" if "True" in cmd_output else "Fail"
                    print("{0:10s} {1:30s} {2:10s}".format(str(device.id), device.name, cmd_return))
        lr_session.close()

    return device_out
   
def massUpdateConfigLR(devicelist, configvalue, isDaemon=False, workers=80, customprofile="default"):
    out = {}
    futures = []
    online_devices_old = []
    online_devices_new = []

    backupfilename = r'cfg-bkp-%s.ini' %hashlib.md5(str(random.randrange(100000,999999)).encode()).hexdigest()
    cfgdir_new = r'C:\ProgramData\CarbonBlack\DataFiles' 
    cfgdir_old = r'C:\Program Files\Confer'
    prop = configvalue.split('=')[0]
    cmds_new = [
        r'"C:\Program Files\Confer\repcli.exe" bypass 1',
        r'cmd.exe /c copy %s\cfg.ini %s\%s' % (cfgdir_new, cfgdir_new, backupfilename),
        r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -NotMatch | %% { $_.Line } > %s\cfg2.ini' % (cfgdir_new, prop, cfgdir_new),
        r'cmd.exe /c move %s\cfg2.ini %s\cfg.ini' % (cfgdir_new, cfgdir_new),
        r'powershell.exe Add-Content %s\cfg.ini "%s"' % (cfgdir_new, configvalue),
        r'"C:\Program Files\Confer\repcli.exe" updateconfig',
        r'"C:\Program Files\Confer\repcli.exe" bypass 0',
        r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -quiet' % (cfgdir_new, configvalue)
    ]
    cmds_old = [
        r'"C:\Program Files\Confer\repcli.exe" bypass 1',
        r'cmd.exe /c copy %s\cfg.ini %s\%s' % (cfgdir_old, cfgdir_old, backupfilename),
        r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -NotMatch | %% { $_.Line } > %s\cfg2.ini' % (cfgdir_old, prop, cfgdir_old),
        r'cmd.exe /c move %s\cfg2.ini %s\cfg.ini' % (cfgdir_old, cfgdir_old),
        r'powershell.exe Add-Content %s\cfg.ini "%s"' % (cfgdir_old, configvalue),
        r'"C:\Program Files\Confer\repcli.exe" updateconfig',
        r'"C:\Program Files\Confer\repcli.exe" bypass 0',
        r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -quiet' % (cfgdir_old, configvalue)
    ]

    for device in devicelist:
        out[device.id] = {}
        version = float(device.sensor_version.split(".")[0] + "." + device.sensor_version.split(".")[1])
        online_devices_new.append(device) if version >= 3.6 else online_devices_old.append(device)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        if not isDaemon:
            print("{0:10} {1:30} {2:10}".format("ID", "Hostname", "Cfg Update"))
        api = CBCloudAPI(profile=customprofile)
        for device in online_devices_new:
            try:
                futures.append(executor.submit(updateConfigFile, api, device, cmds_new, isDaemon))
            except:
                out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"
        for device in online_devices_old:
            try:
                futures.append(executor.submit(updateConfigFile, api, device, cmds_old, isDaemon))
            except:
                out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"

    for f in concurrent.futures.as_completed(futures, timeout=40):
        if f.exception() is None:
            out.update(f.result())
        else:
            out[device.id]["live_response"] = "CONN_FAILED_OR_TIMEOUT"
    return out

def main():
    parser = build_cli_parser("List Devices and Mass Live Response")
    parser.add_argument("-n", "--hostname", help="Query string looking for device names")
    parser.add_argument("-p", "--policy", help="Query string looking for policy names")
    parser.add_argument("-i", "--device_id", action='append', nargs='+', help="Send list of fixed device_id's")
    parser.add_argument("-f", "--if_field", action='append', nargs='+', help="If field equals value. e.g. virtual_machine=true")
    parser.add_argument("-a", "--add_field", action='append', nargs='+', help="Add field(s) to output")
    parser.add_argument("-o", "--only_field", action='append', nargs='+', help="Choose the field(s) to output")
    parser.add_argument("-s", "--simple_output", action='store_true', help="Toggle to only print device_id and device_name")
    parser.add_argument("-t", "--last_connection_timeout", type=int, help="Last Connection tolerated in minutes. Default: 10")
    parser.add_argument("-w", "--workers", type=int, default=80, help="Number of parallel workers (max and default: 80)")
    parser.add_argument("-F", "--find_process", action='append', nargs='+', help="Find process in selected devices")
    parser.add_argument("-K", "--kill_process", action='store_true', help="Toggle to kill matched processes. Needs \"-F\"")
    parser.add_argument("-E", "--execute", action='append', nargs='+', help="Commands to execute on all filtered devices")
    parser.add_argument("-P", "--persist_process", action='store_false', help="Toggle to keep running after the session. Needs \"-E\"")
    parser.add_argument("-U", "--update_cfg", help="Update sensor config file")
    parser.add_argument("-D", "--daemon", action='store_true', help="Toggle for Daemon mode (JSON output)")

    args = parser.parse_args()
    cb = get_cb_cloud_object(args)
    devicelist = cb.select(Device)
    random.seed()
    output = {}

    # Filters:
    if args.hostname:
        devicelist = [d for d in devicelist if (args.hostname).lower() in (d.name).lower()]
    if args.policy:
        devicelist = [d for d in devicelist if (args.policy).lower() in (d.policy_name).lower()]
    if args.device_id:
        if args.device_id[0][0][0] == '@':
            filename = args.device_id[0][0][1:]
            d_ids = []
            with open(filename) as file:
                while line := file.readline():
                    d_ids.append(line.rstrip().lower())
                devicelist = [d for d in devicelist if str(d.id) in d_ids]
        else:
            devicelist = [d for d in devicelist if str(d.id) in flatten(args.device_id)]
    if args.if_field:
        filter = flatten(args.if_field)[0]
        if ">=" in filter:
            field, value = filter.split(">=")
            value = sanitizeValue(value)
            devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and getattr(d, field.lower()) >= value)]
        elif ">" in filter:
            field, value = filter.split(">")
            value = sanitizeValue(value)
            devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and getattr(d, field) >  value)]
        elif "<=" in filter:
            field, value = filter.split("<=")
            value = sanitizeValue(value)
            devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and getattr(d, field) <= value)]
        elif "<" in filter:
            field, value = filter.split("<")
            value = sanitizeValue(value)
            devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and getattr(d, field) <  value)]
        elif "~" in filter:
            field, value = filter.split("~")
            value = sanitizeValue(value)
            if isinstance(value, list) or isinstance(value, str):
                devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and value.upper() in getattr(d, field.lower()).upper())]
        elif "!=" in filter:
            field, value = filter.split("!=")
            value = sanitizeValue(value)
            if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
                devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and getattr(d, field.lower()) != value)]
            elif isinstance(value, str):
                devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and value.lower() != getattr(d, field.lower()).lower())]
            elif isinstance(value, list):
                devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and value.upper() not in getattr(d, field.lower()).upper())]
        elif "=" in filter:
            field, value = filter.split("=")
            value = sanitizeValue(value)
            if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
                devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and getattr(d, field.lower()) == value)]
            elif isinstance(value, str):
                devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and value.lower() == getattr(d, field.lower()).lower())]
            elif isinstance(value, list):
                devicelist = [d for d in devicelist if (hasattr(d, field.lower()) and value.upper() in getattr(d, field.lower()).upper())]
        else:
            devicelist = []

    hasExecutors = (args.execute or args.update_cfg or args.find_process)
    # Initiate JSON output:
    online_devices = []
    if devicelist:
        for d in devicelist:
            output[d.id] = {
                "device_id": d.id, 
                "device_name": d.name,
            }
            if not (args.only_field or args.simple_output):
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
            if hasExecutors or args.last_connection_timeout:
                timeout = args.last_connection_timeout if args.last_connection_timeout else 10
                now = datetime.utcnow()
                delta = timedelta(minutes=timeout)
                if (now - datetime.strptime(d.last_contact_time, FORMAT) >= delta):
                    if hasExecutors:
                        output[d.id]["live_response"] = "OFFLINE"
                    elif args.last_connection_timeout and not hasExecutors:
                        del output[d.id]
                else:
                    online_devices.append(d)
    else:
        print(json.dumps({"device_count": 0, "results": None}, indent=2, sort_keys=False))
        sys.exit()

    # Presenters:
    if args.add_field or args.only_field:
        fields = flatten(args.add_field) if args.add_field else flatten(args.only_field)
        for d in devicelist:
            for field in fields:
                output[d.id].update({ field: getattr(d, field.lower()) }) if hasattr(d, field.lower()) else None

    if args.device_id:
        if args.device_id[0][0][0] == '@':
            filename = args.device_id[0][0][1:]
            d_ids = []
            with open(filename) as file:
                while line := file.readline():
                    d_ids.append(line.rstrip().lower())
                devicelist = [d for d in devicelist if str(d.id).lower() in d_ids]

    # Executors:
    if hasExecutors:
        if args.execute:
            if args.execute[0][0][0] == '@':
                filename = args.execute[0][0][1:]
                commands = []
                with open(filename) as file:
                    while line := file.readline():
                        commands.append(line.rstrip())
                merge(output, massExecuteLR(online_devices, commands, args.persist_process, args.daemon, args.workers, args.profile).copy())
            else:
                merge(output, massExecuteLR(online_devices, flatten(args.execute), args.persist_process, args.daemon, args.workers, args.profile).copy())
        elif args.find_process:
            if args.find_process[0][0][0] == '@':
                filename = args.find_process[0][0][1:]
                processes = []
                with open(filename) as file:
                    while line := file.readline():
                        processes.append(line.rstrip())
                merge(output, massFindAndKillLR(online_devices, processes, args.kill_process, args.daemon, args.workers, args.profile).copy())
            else:
                merge(output, massFindAndKillLR(online_devices, flatten(args.find_process), args.kill_process, args.daemon, args.workers, args.profile).copy())
        elif args.update_cfg and sanitizeUpdateCfg(args.update_cfg):
            merge(output, massUpdateConfigLR(online_devices, args.update_cfg, args.daemon, args.workers, args.profile).copy())

    # If not command-line execution or is Daemon, print JSON output:
    if devicelist and (args.daemon or not hasExecutors):
        print(json.dumps({"device_count": len(output), "results": output}, indent=2, sort_keys=False))

if __name__ == "__main__":
    main()
