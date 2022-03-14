# lrtool
VMware Carbon Black Cloud command line tool for querying Devices and Mass Live Response

The idea of this tool is to query VMware Carbon Black Cloud (CBC) Devices filtering down (see `FILTERS`), then print-only (see `PRESENTERS`) or run massive commands via Live Response using multithreads (see `EXECUTORS`).

This was tested in python v3.10 on a MacOS Big Sur.

## Current Features
- Filter devices based on a number of criteria or file list with device_ids (one per line).
- Find processes by name/path contains or cmdline contains, optionally kill it.
- Execute commands across all selected/filtered devices. Can let it running after the session (persistence).
- Change a [property from cfg.ini](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/cbc-sensor-installation-guide/GUID-0FBA8BFB-8E3D-42FB-A589-8E31B184591B.html) (**EXPERIMENTAL, DANGEROUS, UNSUPPORTED and HIGH RISK OF BREAKING THINGS - CONSULT YOUR VMW REPRESENTATIVE**)
- Option to output in JSON, to use the tool as a backend application supplying a webserver.

## Install Requirements
```
python3.10 -m pip install carbon-black-cloud-sdk
```

## Install
### Latest (ongoing, not extensively tested)
```
git clone https://github.com/0xleone/lrtool
cd lrtool
```
### Stable (tested in multiple scenarios)
```
Go to RELEASES page.
```

## Edit the credentials file
First, create the credentials file with the right permissions:
```
mkdir .carbonblack
touch .carbonblack/credentials.cbc
chmod 500 .carbonblack
chmod 600 .carbonblack/credentials.cbc
```

Now, edit the file:
```
[default]
url=https://defense-prod05.conferdeploy.net
token=XXXXXXXXXXXXXXXXXXXXXXXX/YYYYYYYYYY
org_key=ZZZZZZZZ

[test]
url=https://defense-prod05.conferdeploy.net
token=XXXXXXXXXXXXXXXXXXXXXXXX/YYYYYYYYYY
org_key=ZZZZZZZZ

[production]
url=https://defense-prod06.conferdeploy.net
token=XXXXXXXXXXXXXXXXXXXXXXXX/YYYYYYYYYY
org_key=ZZZZZZZZ
```
More [here](https://carbon-black-cloud-python-sdk.readthedocs.io/en/latest/authentication/#with-a-file)

## Current Options:

Legend:
```
C.I.: Case Insensitive
S.M.: Support Multiple Ocurrences
```

| Param |             Description            | C.I | S.M |
| :--:  | ---------------------------------- | :-: | :-: |
| `-n`  | device_name or part of             |  X  |     |
| `-p`  | policy_name or part of             |  X  |     |
| `-i`  | device with provided device_id     |     |  X  |
| `-f`  | if field (=,!=,>,>=,<,<=) value    |  X  |  X  |
| `-a`  | add selected field to output       |  X  |  X  |
| `-o`  | only output selected field         |  X  |  X  |
| `-s`  | toggle for simpler output          |     |     |
| `-t`  | max min. from last connection      |     |     |
| `-w`  | max number of thread workers       |     |     |
| `-d`  | toggle to print output in JSON     |     |     |
| `-P`  | find process across devices        |  X  |  X  |
| `-K`  | toggle to kill -P processes        |     |     |
| `-E`  | command to run on devices          |     |  X  |
| `-N`  | toggle to "nohup" -E processes     |     |     |
| `-U`  | update sensor cfg file             |     |     |
| `-l`  | List request directory             |     |     |
| `-r`  | List request regkey                |     |     |
|`--file_print`| Print File                  |     |     |
|`--file_upload`| Upload File into devices   |     |     |
|`--file_del`| Delete Files                  |     |  X  |
|`--reg_get`| Print Regkey                   |     |     |
|`--reg_set`| Set/Update Regkey              |     |     |
|`--reg_del`| Delete Regkey                  |     |  X  |


## Sample Filters
<details>
  <summary>No filters (all devices with default fields)</summary>

```
python3.10 lrtool.py

{
  "device_count": 3,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "last_contact_time": "2022-02-17T17:16:03.521Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 888888,
      "policy_name": "Standard",
      "current_sensor_policy_name": "Standard",
      "mac_address": "005056b816e1",
      "last_internal_ip_address": "10.10.10.1",
      "last_external_ip_address": "200.200.200.200",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U1234567"
    },
    "22222222": {
      "device_id": 22222222,
      "device_name": "DOMAIN\\Machine02",
      "last_contact_time": "2022-02-17T17:15:47.658Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 999999,
      "policy_name": "Monitored",
      "current_sensor_policy_name": "Monitored",
      "mac_address": "005056b83d19",
      "last_internal_ip_address": "10.10.10.2",
      "last_external_ip_address": "200.200.200.201",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U2345678"
    },
    "33333333": {
      "device_id": 33333333,
      "device_name": "DOMAIN\\Server20",
      "last_contact_time": "2022-02-17T17:15:47.658Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 999999,
      "policy_name": "Monitored",
      "current_sensor_policy_name": "Monitored",
      "mac_address": "005056b83d19",
      "last_internal_ip_address": "10.10.10.3",
      "last_external_ip_address": "200.200.200.201",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U3456789"
    },
``` 
</details>
<details>
  <summary>By "device name contains" and use different profile ("default" if omitted):</summary>

```
python3.10 lrtool.py --profile test -n Server

{
  "device_count": 1,
  "results": {
    "33333333": {
      "device_id": 33333333,
      "device_name": "DOMAIN\\Server20",
      "last_contact_time": "2022-02-17T17:15:47.658Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 999999,
      "policy_name": "Monitored",
      "current_sensor_policy_name": "Monitored",
      "mac_address": "005056b83d19",
      "last_internal_ip_address": "10.10.10.3",
      "last_external_ip_address": "200.200.200.201",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U3456789"
    }
  }
}
```
</details>
<details>
  <summary>By "policy name contains":</summary>
  
```
python3.10 lrtool.py -n Machine -p Standard

{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "last_contact_time": "2022-02-17T17:16:03.521Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 888888,
      "policy_name": "Standard",
      "current_sensor_policy_name": "Standard",
      "mac_address": "005056b816e1",
      "last_internal_ip_address": "10.10.10.1",
      "last_external_ip_address": "200.200.200.200",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U1234567"
    }
  }
}
```
</details>
<details>
  <summary>By property value (=:equals, ~:contains)</summary>

```
#python3.10 lrtool.py -n Machine -p Standard -f "os~WIND"
python3.10 lrtool.py -n Machine -p Standard -f os=WINDOWS

{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "last_contact_time": "2022-02-17T17:16:03.521Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 888888,
      "policy_name": "Standard",
      "current_sensor_policy_name": "Standard",
      "mac_address": "005056b816e1",
      "last_internal_ip_address": "10.10.10.1",
      "last_external_ip_address": "200.200.200.200",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U1234567"
    }
  }
}
```
</details>
<details>
  <summary>By list of device_ids in a file (one device_id per line):</summary>

```
cat "/path/to/file"
11111111

python3.10 lrtool.py -Di "@/path/to/file"
{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "last_contact_time": "2022-02-17T17:16:03.521Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 888888,
      "policy_name": "Standard",
      "current_sensor_policy_name": "Standard",
      "mac_address": "005056b816e1",
      "last_internal_ip_address": "10.10.10.1",
      "last_external_ip_address": "200.200.200.200",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U1234567"
    }
  }
}
```
</details>

## Presenters
<details>
  <summary>Add field to output:</summary>

```
python3.10 lrtool.py -n Machine -p Standard -a virtual_machine

{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "last_contact_time": "2022-02-17T17:16:03.521Z",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "policy_id": 888888,
      "policy_name": "Standard",
      "current_sensor_policy_name": "Standard",
      "mac_address": "005056b816e1",
      "last_internal_ip_address": "10.10.10.1",
      "last_external_ip_address": "200.200.200.200",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "deployment_type": "WORKLOAD",
      "uninstall_code": "U1234567"
      "virtual_machine": true
    }
  }
}
```
</details>
<details>
  <summary>Simple output. Can be used alongside multiple `-a`:</summary>

```
python3.10 lrtool.py -n Machine -p Standard -sa virtual_machine os  # Same as "-s -a"

{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "virtual_machine": true,
      "os": "WINDOWS"
    }
  }
}
```
</details>
<details>
  <summary>Select fields to output (`device_id` and `device_name` will always show up):</summary>

```
python3.10 lrtool.py -n Machine -p Standard -o virtual_machine

{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "virtual_machine": true
    }
  }
}
```
</details>

## Executors
#### Execute command(s):
<details>
  <summary>Asynchronous execute one or more commands on all selected devices:</summary>

```
#python3.10 lrtool.py -n Machine -E "cmd.exe /c echo hello" -E "cmd.exe /c echo world"  # Multiple "-E"
python3.10 lrtool.py -n Machine -E "cmd.exe /c echo hello" "cmd.exe /c echo world"      # Single "-E"

11111111| cmd.exe /c echo hello
hello

22222222| cmd.exe /c echo hello
hello

22222222| cmd.exe /c echo world
world

11111111| cmd.exe /c echo world
world
```
</details>
<details>
  <summary>Execute and keep it running in background:</summary>

```
python3.10 lrtool.py -p Standard -NE "cmd.exe /c ping 1.1.1.1 -t"
11111111|DOMAIN\Machine01 ❯ "cmd.exe /c ping 1.1.1.1 -t" ❯ RUNNING_ON_BACKGROUND
```
</details>


#### Find and Kill processes:
<details>
  <summary>Find all devices that have "ping" in a process_name or process_path:</summary>

```
python3.10 lrtool.py -p Standard -NE "cmd.exe /c ping 1.1.1.1 -t"
11111111|DOMAIN\Machine01 ❯ "cmd.exe /c ping 1.1.1.1 -t" ❯ RUNNING_ON_BACKGROUND

python3.10 lrtool.py -p Standard -P "ping"
11111111|DOMAIN\Machine01 ❯ "ping" ❯ FOUND (PID: 7680)
11111111|DOMAIN\Machine01 ❯ "ping" ❯ FOUND (PID: 1408)

python3.10 lrtool.py -p Standard -sDP "ping"
{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "live_response": {
        "find_processes": {
          "ping": {
            "status": "FOUND",
            "matches_count": 2,
            "matches_pid": [
              7680,
              1408
            ],
            "matches_details": {
              "7680": {
                "process_pid": 7680,
                "process_path": "c:\\windows\\system32\\cmd.exe",
                "process_cmdline": "cmd.exe /c ping 1.1.1.1 -t",
                "sid": "S-1-5-18",
                "process_username": "NT AUTHORITY\\SYSTEM",
                "parent_pid": 11488,
                "parent_create_time": 1645578703,
                "process_create_time": 1645578.0
              },
              "1408": {
                "process_pid": 1408,
                "process_path": "c:\\windows\\system32\\ping.exe",
                "process_cmdline": "ping  1.1.1.1 -t",
                "sid": "S-1-5-18",
                "process_username": "NT AUTHORITY\\SYSTEM",
                "parent_pid": 7680,
                "parent_create_time": 1645578704,
                "process_create_time": 1645578.0
              }
            }
          }
        }
      }
    }
  }
}

python3.10 lrtool.py -p Standard -KP "ping"
11111111|DOMAIN\Machine01 ❯ "ping" ❯ KILLED (PID: 7680)
11111111|DOMAIN\Machine01 ❯ "ping" ❯ KILLED (PID: 1408)
```
</details>

#### Update cfg.ini in all selected devices:
Remotely change a given `cfg.ini` property across all selected devices:

#### DISCLAIMER: DO NOT CHANGE ANYTHING IN THIS FILE IF YOU AREN'T 100% CONFIDENT. PLEASE CONSULT YOUR VMW CARBON BLACK REPRESENTATIVE FOR QUESTIONS. This tool is shared "as is", is not official and the author DO NOT take responsabilities if anything breaks.

Also, for safety reasons only the following options are accepted by this script using simple input sanitization: 'AmsiEnabled', 'CBLR', 'AuthenticatedCLIUsers', 'ProxyServer' and 'ProxyServerCredentials'.

<details>
  <summary>Option A) Regular output:</summary>

```
python3.10 lrtool.py -n Machine -U "AuthenticatedCLIUsers=S-1-5-32-544"

ID         Hostname                       Cfg Update
11111111   DOMAIN\\Machine01              Success   
22222222   DOMAIN\\Machine02              Success
```
</details>
<details>
  <summary>Option B) JSON output:</summary>

```
python3.10 lrtool.py -n Machine -p Standard -sDU "AuthenticatedCLIUsers=S-1-5-32-544"

{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "live_response": {
        "config_update": true
      }
    }
  }
}
```
</details>

### More advanced samples:
<details>
  <summary>Combine Toggle options:</summary>

```
python3.10 lrtool.py -Dp Standard -o virtual_machine os

{
  "device_count": 1,
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "virtual_machine": true,
      "os": "WINDOWS"
    }
  }
}
```
</details>
<details>
  <summary>Read a list of commands in a file:</summary>

```
cat "/path/to/file"
cmd.exe /c echo hello
cmd.exe /c echo world
  
python3.10 lrtool.py -E "@/path/to/file"
11111111|DOMAIN\Machine01 ❯ cmd.exe /c echo hello
hello

11111111|DOMAIN\Machine01 ❯ cmd.exe /c echo world
world
```
</details>

## Protips:
- If you need to export this to CSV or just want to see results in tabular format (replace @csv with @tsv), you can run this:
```
python3.10 lrtool.py (...) | jq -r '{results} | .[] | [.[]] | (.[1] | keys_unsorted), (.[] | [.[]]) | @csv'
```

## TODO 
- Windows Registry operations
- User interface using Flask and VMware opensource https://clarity.design

## Main Sources: 
https://developer.carbonblack.com \
https://carbon-black-cloud-python-sdk.readthedocs.io \
https://github.com/carbonblack/carbon-black-cloud-sdk-python \
https://github.com/carbonblack/carbon-black-cloud-sdk-python/blob/develop/examples/platform/list_devices.py \
https://stackoverflow.com

## Special thanks: 
https://github.com/j3r3mias - Everytime I got stuck in Python shenanigans, you guided me. Thanks bro.
