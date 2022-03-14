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

import json, hashlib, random, base64, re, sys, concurrent.futures
from mergedeep import merge
from cbc_sdk.helpers import build_cli_parser, get_cb_cloud_object
from cbc_sdk.platform import Device
from cbc_sdk import CBCloudAPI
from datetime import datetime, timedelta
FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

def b64output(text):
    return base64.b64encode(text.encode('ascii')).decode('ascii')

def flattenArgs(nestedlist):
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

def execLR(device, args, executors):
    api = CBCloudAPI(profile=args.profile)
    with api.live_response.request_session(device.id) as lr_session:
        device_out = { device.id: { "live_response": {} } }
        wait = False if args.nohup else True
        if "execute" in executors:
            count = 0
            device_out[device.id]["live_response"]["exec"] = {}
            for command in executors["execute"]:
                try:
                    if wait:
                        cmd_output = '\n'+lr_session.create_process(r'%s' %command, wait_for_output=True, wait_for_completion=True).decode('ascii')
                    else:
                        lr_session.create_process(r'%s' %command, wait_for_output=False, wait_for_completion=False)
                        cmd_output = "RUNNING_ON_BACKGROUND"
                    device_out[device.id]["live_response"]["exec"][count] = {
                        b64output(command): (b64output(cmd_output) if wait else cmd_output)
                    }
                    count += 1
                    if not args.daemon:
                        print(r'%s|%s ❯ EXECUTE ❯ %s ❯ %s' % (device.id, device.name, command, cmd_output))
                except:
                    device_out[device.id]["live_response"]["exec"] = "FAILED"
        if "find_process" in executors:
            device_out[device.id]["live_response"]["find"] = {}
            match_processes = []
            running_processes = lr_session.list_processes()

            for pname in executors["find_process"]:
                device_out[device.id]["live_response"]["find"][pname] = {"status": "NOT_FOUND", "matches_count": 0, "matches_pid": [], "matches_details": {} }
                match = False
                for process in running_processes:
                    if ((pname.lower() in (process["process_path"]).lower()) or (pname.lower() in (process["process_cmdline"]).lower())):
                        match = True
                        match_processes.append(process["process_pid"])
                        device_out[device.id]["live_response"]["find"][pname]["status"] = "KILLED" if args.kill_process else "FOUND"
                        device_out[device.id]["live_response"]["find"][pname]["matches_count"] += 1
                        device_out[device.id]["live_response"]["find"][pname]["matches_pid"].append(process["process_pid"])
                        device_out[device.id]["live_response"]["find"][pname]["matches_details"][process["process_pid"]] = process
                        if not args.daemon:
                            print(r'%s|%s ❯ FIND_PROCESS ❯ %s ❯ %s (PID: %s)' % (device.id, device.name, "\""+pname+"\"", device_out[device.id]["live_response"]["find"][pname]["status"], process["process_pid"]))
                if not match and not args.daemon:
                    print(r'%s|%s ❯ FIND_PROCESS ❯ %s ❯ %s' % (device.id, device.name, "\""+pname+"\"", device_out[device.id]["live_response"]["find"][pname]["status"]))

            if args.kill_process and len(match_processes) > 0:
                for pid in match_processes:
                    lr_session.kill_process(pid)
        if "update_cfg" in executors:
            device_out[device.id]["live_response"]["config_updated"] = False
            count = 0
            for command in executors["update_cfg"]:
                lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True)
                count += 1
                if count == 8:
                    cmd_output = lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True).decode('ascii')
                    device_out[device.id]["live_response"]["config_updated"] = True if "True" in cmd_output else False
                    if not args.daemon:
                        cmd_return = "SUCCESS" if "True" in cmd_output else "FAILED"
                        print(r'%s|%s ❯ UPDATE_CONFIG ❯ %s' %(device.id, device.name, cmd_return))
        if "list_dir" in executors:
            command = (r'cmd.exe /c dir %s' %(executors["list_dir"][0])) if device.os == "WINDOWS" else (r'ls -lha %s' %(executors["list_dir"][0]))
            try:
                cmd_output = lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True).decode('ascii')
                device_out[device.id]["live_response"]["list_dir"] = { command: b64output(cmd_output) }
                if not args.daemon:
                    print(r'%s|%s ❯ LIST_DIR ❯ %s' %(device.id, device.name, command) +'\n'+cmd_output)
            except:
                device_out[device.id]["live_response"]["list_dir"] = "FAILED"
                if not args.daemon:
                    print(r'%s|%s ❯ LIST_DIR ❯ %s' %(device.id, device.name, command) +'\n'+"COMMAND_FAILED")
        if "list_reg" in executors:
            try:
                reg_list = lr_session.list_registry_keys_and_values(executors["list_reg"][0])
                device_out[device.id]["live_response"]["list_reg"] = { executors["list_reg"][0]: reg_list }
                if not args.daemon:
                    if reg_list['sub_keys']:
                        for r in reg_list['sub_keys']:
                            print(r'%s|%s ❯ LIST_REG ❯ name: %s ❯ type: SUB_KEY ❯ value: N/A' %(device.id, device.name, r))
                    if reg_list['values']:
                        for r in reg_list['values']:
                            print(r'%s|%s ❯ LIST_REG ❯ name: %s ❯ type: %s ❯ value: %s' %(device.id, device.name, r['registry_name'], r['registry_type'][2:], r['registry_data']))
            except:
                device_out[device.id]["live_response"]["list_reg"] = { executors["list_reg"][0]: "NOT_FOUND" }
                if not args.daemon:
                    print(r'%s|%s ❯ LIST_REG ❯ name: NOT_FOUND ❯ type: N/A ❯ value: N/A' %(device.id, device.name))
        if "file_print" in executors:
            command = (r'cmd.exe /c type %s' %(executors["file_print"][0])) if device.os == "WINDOWS" else (r'cat %s' %(executors["file_print"][0]))
            try:
                cmd_output = lr_session.create_process(r'%s' %command, wait_for_completion=True, wait_for_output=True).decode('ascii')
                device_out[device.id]["live_response"]["file_print"] = { command: b64output(cmd_output) }
                if not args.daemon:
                    print(r'%s|%s ❯ FILE_PRINT ❯ %s' %(device.id, device.name, command) +'\n'+cmd_output)
            except:
                device_out[device.id]["live_response"]["file_print"] = "FAILED"
                if not args.daemon:
                    print(r'%s|%s ❯ FILE_PRINT ❯ %s' %(device.id, device.name, command) +'\n'+"COMMAND_FAILED")
        if "file_upload" in executors:
            device_out[device.id]["live_response"]["file_upload"] = { "success": [], "failed": [] }
            success, failed = [], []
            local_file, remote_file = executors["file_upload"]
            f = open(local_file, "rb")
            if not f.closed:
                lr_session.put_file(f, remote_file)
                f.close()
                success.append({ local_file: remote_file })
                if not args.daemon:
                    print(r'%s|%s ❯ FILE_UPLOAD ❯ %s ❯ SUCCESS' %(device.id, device.name, local_file))
            else:
                failed.append({ local_file: remote_file })
                if not args.daemon:
                    print(r'%s|%s ❯ FILE_UPLOAD ❯ %s ❯ FAILED' %(device.id, device.name, local_file))
            if success:
                device_out[device.id]["live_response"]["file_upload"]["success"] = success
            if failed:
                device_out[device.id]["live_response"]["file_upload"]["failed"] = failed
        if "file_del" in executors:
            deleted, not_found, files_to_delete = [], [], []
            device_out[device.id]["live_response"]["file_del"] = { "deleted": [], "not_found": [] }
            for arg in executors["file_del"]:
                if arg[0] == '@':
                    with open(arg[1:]) as f:
                        while line := f.readline():
                            files_to_delete.append(line.rstrip())
                else:
                    files_to_delete.append(arg.rstrip())
            for file in files_to_delete:
                try:
                    lr_session.delete_file(file)
                    deleted.append(file)
                    if not args.daemon:
                        print(r'%s|%s ❯ FILE_DELETE ❯ %s ❯ DELETED' %(device.id, device.name, file))
                except:
                    not_found.append(file)
                    if not args.daemon:
                        print(r'%s|%s ❯ FILE_DELETE ❯ %s ❯ NOT_FOUND_OR_ACCESS_DENIED' %(device.id, device.name, file))
            if deleted:
                device_out[device.id]["live_response"]["file_del"]["deleted"] = deleted
            if not_found:
                device_out[device.id]["live_response"]["file_del"]["not_found"] = not_found
        if "reg_get" in executors:
            try:
                reg = lr_session.get_registry_value(executors["reg_get"][0])
                device_out[device.id]["live_response"]["reg_get"] = { executors["reg_get"][0]: reg }
                if not args.daemon:
                    print(r'%s|%s ❯ REGKEY_GET ❯ name: %s ❯ type: %s ❯ value: %s' %(device.id, device.name, reg['registry_name'], reg['registry_type'][2:], reg['registry_data']))
            except:
                device_out[device.id]["live_response"]["reg_get"][0] = "NOT_FOUND"
                if not args.daemon:
                    print(r'%s|%s ❯ REGKEY_GET ❯ name: %s ❯ type: %s ❯ value: %s' %(device.id, device.name, "NOT_FOUND", "N/A", "N/A"))
        if "reg_set" in executors:
            try:
                k, v, t = executors["reg_set"]
                lr_session.set_registry_value(regkey=k, value=v, value_type=t)
                ret = lr_session.get_registry_value(k)
                device_out[device.id]["live_response"]["reg_set"] = { k: ret }
                if not args.daemon:
                    print(r'%s|%s ❯ REGKEY_SET ❯ name: %s ❯ type: %s ❯ value: %s' %(device.id, device.name, reg['registry_name'], reg['registry_type'][2:], reg['registry_data']))
            except:
                device_out[device.id]["live_response"]["reg_set"] = "FAILED"
                if not args.daemon:
                    print(r'%s|%s ❯ REGKEY_SET ❯ name: %s ❯ type: %s ❯ value: %s' %(device.id, device.name, "FAILED", "N/A", "N/A"))
        if "reg_del" in executors:
            deleted, not_found, regkeys_to_delete = [], [], []
            device_out[device.id]["live_response"]["reg_del"] = { "deleted": [], "not_found": [] }
            for arg in executors["reg_del"]:
                if arg[0] == '@':
                    with open(arg[1:]) as f:
                        while line := f.readline():
                            regkeys_to_delete.append(line.rstrip())
                else:
                    regkeys_to_delete.append(arg)
            for regkey in regkeys_to_delete:
                try:
                    lr_session.delete_registry_value(regkey)
                    deleted.append(regkey)
                    if not args.daemon:
                        print(r'%s|%s ❯ REGKEY_DELETE ❯ %s ❯ DELETED' %(device.id, device.name, regkey))
                except:
                    not_found.append(regkey)
                    if not args.daemon:
                        print(r'%s|%s ❯ REGKEY_DELETE ❯ %s ❯ NOT_FOUND_OR_ACCESS_DENIED' %(device.id, device.name, regkey))
            if deleted:
                device_out[device.id]["live_response"]["reg_del"]["deleted"] = deleted
            if not_found:
                device_out[device.id]["live_response"]["reg_del"]["not_found"] = not_found
        lr_session.close()
        return device_out
    # If not possible to connect:
    return({ device.id: { "live_response": "CONN_FAILED_OR_TIMEOUT" }})

def manageExecutors(online_devices, args):       
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        out = {}
        futures = []
        if args.update_cfg:
            backupfilename = r'cfg-bkp-%s.ini' %hashlib.md5(str(random.randrange(100000,999999)).encode()).hexdigest()
            cfgdir_new = r'C:\ProgramData\CarbonBlack\DataFiles' 
            cfgdir_old = r'C:\Program Files\Confer'
            prop = (args.update_cfg).split('=')[0]
            cmds_new = [
                r'"C:\Program Files\Confer\repcli.exe" bypass 1',
                r'cmd.exe /c copy %s\cfg.ini %s\%s' % (cfgdir_new, cfgdir_new, backupfilename),
                r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -NotMatch | %% { $_.Line } > %s\cfg2.ini' % (cfgdir_new, prop, cfgdir_new),
                r'cmd.exe /c move %s\cfg2.ini %s\cfg.ini' % (cfgdir_new, cfgdir_new),
                r'powershell.exe Add-Content %s\cfg.ini "%s"' % (cfgdir_new, args.update_cfg),
                r'"C:\Program Files\Confer\repcli.exe" updateconfig',
                r'"C:\Program Files\Confer\repcli.exe" bypass 0',
                r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -quiet' % (cfgdir_new, args.update_cfg)
            ]
            cmds_old = [
                r'"C:\Program Files\Confer\repcli.exe" bypass 1',
                r'cmd.exe /c copy %s\cfg.ini %s\%s' % (cfgdir_old, cfgdir_old, backupfilename),
                r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -NotMatch | %% { $_.Line } > %s\cfg2.ini' % (cfgdir_old, prop, cfgdir_old),
                r'cmd.exe /c move %s\cfg2.ini %s\cfg.ini' % (cfgdir_old, cfgdir_old),
                r'powershell.exe Add-Content %s\cfg.ini "%s"' % (cfgdir_old, args.update_cfg),
                r'"C:\Program Files\Confer\repcli.exe" updateconfig',
                r'"C:\Program Files\Confer\repcli.exe" bypass 0',
                r'powershell.exe Get-Content %s\cfg.ini | Select-String -Pattern %s -quiet' % (cfgdir_old, args.update_cfg)
            ]
        
        for device in online_devices:
            executors = {}
            # Prepare tasks:
            if args.execute:
                commands = []
                if args.execute[0][0][0] == '@':
                    filename = args.execute[0][0][1:]
                    with open(filename) as file:
                        while line := file.readline():
                            commands.append(line.rstrip())
                else:
                    commands = flattenArgs(args.execute)
                executors["execute"] = commands
            if args.find_process:
                processes = []
                if args.find_process[0][0][0] == '@':
                    filename = args.find_process[0][0][1:]
                    with open(filename) as file:
                        while line := file.readline():
                            processes.append(line.rstrip())
                else:
                    processes = flattenArgs(args.find_process)
                executors["find_process"] = processes
            if args.update_cfg and sanitizeUpdateCfg(args.update_cfg):
                version = float(device.sensor_version.split(".")[0] + "." + device.sensor_version.split(".")[1])
                if version >= 3.6:
                    executors["update_cfg"] = cmds_new
                else:
                    executors["update_cfg"] = cmds_old
            if args.list_dir:
                executors["list_dir"] = flattenArgs(args.list_dir)
            if args.list_reg:
                executors["list_reg"] = flattenArgs(args.list_reg)
            if args.file_print:
                executors["file_print"] = flattenArgs(args.file_print)
            if args.file_upload:
                executors["file_upload"] = flattenArgs(args.file_upload)
            if args.file_del:
                executors["file_del"] = flattenArgs(args.file_del)
            if args.reg_get:
                executors["reg_get"] = flattenArgs(args.reg_get)
            if args.reg_set and (len(flattenArgs(args.reg_set)) == 3):
                executors["reg_set"] = flattenArgs(args.reg_set)
            if args.reg_del:
                executors["reg_del"] = flattenArgs(args.reg_del)

            # Submit:
            futures.append(executor.submit(execLR, device, args, executors))

        for f in concurrent.futures.as_completed(futures):
            if f.exception() is None:
                out.update(f.result())
            else:
                out = { device.id: { "live_response": "CONN_FAILED_OR_TIMEOUT" }}
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
    parser.add_argument("-D", "--daemon", action='store_true', help="Toggle for Daemon mode (JSON output)")
    parser.add_argument("-P", "--find_process", action='append', nargs='+', help="Find process in selected devices")
    parser.add_argument("-K", "--kill_process", action='store_true', help="Toggle to kill matched processes. Needs \"-P\"")
    parser.add_argument("-E", "--execute", action='append', nargs='+', help="Commands to execute on all filtered devices")
    parser.add_argument("-N", "--nohup", action='store_true', help="Toggle to keep running after the session. Needs \"-E\"")
    parser.add_argument("-U", "--update_cfg", help="Update sensor config file")
    parser.add_argument("-l", "--list_dir", action='append', nargs=1, help="List Directory")
    parser.add_argument("-r", "--list_reg", action='append', nargs=1, help="List Regkey, subdirs and values")
    parser.add_argument("--file_print", action='append', nargs=1, help="Print File")
    parser.add_argument("--file_upload", action='append', nargs=2, help="Local file to upload and remote file location (2 args)")
    parser.add_argument("--file_del", action='append', nargs='+', help="Delete File")
    parser.add_argument("--reg_get", action='append', nargs=1, help="Get Registry Key")
    parser.add_argument("--reg_set", action='append', nargs=3, help="Regkey, value and type to set (3 args)")
    parser.add_argument("--reg_del", action='append', nargs='+', help="Delete Registry Key")

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
            devicelist = [d for d in devicelist if str(d.id) in flattenArgs(args.device_id)]
    if args.if_field:
        filter = flattenArgs(args.if_field)[0]
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

    hasExecutors = (
                    args.execute or args.update_cfg or args.find_process or args.list_dir or 
                    args.list_reg or args.file_print or args.file_upload or args.file_del or 
                    args.reg_get or args.reg_set or args.reg_del
                   )
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

    if args.device_id and args.device_id[0][0][0] == '@':
            filename = args.device_id[0][0][1:]
            d_ids = []
            with open(filename) as file:
                while line := file.readline():
                    d_ids.append(line.rstrip().lower())
                devicelist = [d for d in devicelist if str(d.id).lower() in d_ids]

    # Presenters:
    if args.add_field or args.only_field:
        fields = flattenArgs(args.add_field) if args.add_field else flattenArgs(args.only_field)
        for d in devicelist:
            for field in fields:
                output[d.id].update({ field: getattr(d, field.lower()) }) if hasattr(d, field.lower()) else None

    # Executors:
    if hasExecutors:
        merge(output, manageExecutors(online_devices, args).copy())

    # If not command-line execution or is Daemon, print JSON output:
    if devicelist and (args.daemon or not hasExecutors):
        print(json.dumps({"device_count": len(output), "results": output}, indent=2, sort_keys=False))

if __name__ == "__main__":
    main()
