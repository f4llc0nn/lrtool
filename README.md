# lrtool
Carbon Black Cloud command line tool for querying Devices and Mass Live Response

The idea of this tool is to query VMware Carbon Black Cloud (CBC) Devices filtering down (FILTERS), then print-only (PRESENTERS) or run massive commands via Live Response using multithreads (EXECUTORS).

This was tested in python v3.10 on a MacOS Big Sur.

## Install Requirements
```
python3.10 -m pip install carbon-black-cloud-sdk
```

## Install
```
git clone https://github.com/0xleone/lrtool
cd lrtool
```

## Edit the credentials file
More [here](https://carbon-black-cloud-python-sdk.readthedocs.io/en/latest/authentication/#with-a-file)
First, create the credentials file with the right permissions:
```
mkdir .carbonblack
chmod 500 .carbonblack
touch .carbonblack/credentials.cbc
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

## Sample Filters
No filters (all devices with default fields)
```
python3.10 lrtool.py

{
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

filter by "device name contains":
```
python3.10 lrtool.py -n Server

{
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

also add filter by "policy name contains":
```
python3.10 lrtool.py -n Machine -g Standard

{
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

## Presenters
Add field to output:
```
python3.10 lrtool.py -n Machine -g Standard -a virtual_machine

{
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

Select fields to output (`device_id` and `device_name` will always show up):
```
python3.10 lrtool.py -n Machine -g Standard -f virtual_machine

{
  "results": {
    "11111111": {
      "device_id": 11111111,
      "device_name": "DOMAIN\\Machine01",
      "virtual_machine": true
    }
  }
}
```

## Executors
#### Example #1:
Assynchronous execute one or more commands on all selected devices:
```
python3.10 lrtool.py -n Machine -E "cmd.exe /c echo hello" "cmd.exe /c echo world"

11111111| cmd.exe /c echo hello
hello

22222222| cmd.exe /c echo hello
hello

22222222| cmd.exe /c echo world
world

11111111| cmd.exe /c echo world
world
```

#### Example #2:
Remotely change a given `cfg.ini` property across all selected devices:

#### DISCLAIMER: DO NOT CHANGE ANYTHING IN THIS FILE IF YOU AREN'T 100% CONFIDENT. PLEASE CONSULT YOUR CARBON BLACK REPRESENTATIVE FOR QUESTIONS. This tool is shared "as is", is not official and the author DO NOT take responsabilities for your own doing.

Also, for safety reasons only the following options are accepted by this script using simple input sanitization: 'AmsiEnabled', 'CBLR', 'AuthenticatedCLIUsers', 'ProxyServer' and 'ProxyServerCredentials'.

If you also add -D at the end, it will wait for all devices to finish it's tasks and will print a JSON ready to be consumed by an application. Otherwise, it will just print every command related (eight) in every machine. The commands are numbered in order of execution and it's encoded in base64 to avoid issues with special chars.

```
python3.10 lrtool.py -n Machine -g Standard -f virtual_machine -U "AuthenticatedCLIUsers=S-1-5-32-544" -D

{
  "results": {
    "71388794": {
      "device_id": 71388794,
      "device_name": "SAMBARI0\\RDSSambari",
      "os": "WINDOWS",
      "os_version": "Windows Server 2019 x64",
      "sensor_version": "3.7.0.1503",
      "deployment_type": "WORKLOAD",
      "policy_id": 233733,
      "policy_name": "Monitored",
      "current_sensor_policy_name": "Monitored",
      "mac_address": "005056b816e1",
      "last_internal_ip_address": "10.92.239.81",
      "last_external_ip_address": "66.170.99.2",
      "last_contact_time": "2022-02-17T17:45:51.209Z",
      "scan_status": null,
      "passive_mode": false,
      "quarantined": false,
      "vulnerability_score": 5.1,
      "vulnerability_severity": "MODERATE",
      "uninstall_code": "931HDEGF",
      "live_response": {
        "0": {
          "IkM6XFByb2dyYW0gRmlsZXNcQ29uZmVyXHJlcGNsaS5leGUiIGJ5cGFzcyAx": "U2Vuc29yIGlzIGluIGJ5cGFzcyBtb2RlDQo="
        },
        "1": {
          "Y21kLmV4ZSAvYyBjb3B5IEM6XFByb2dyYW1EYXRhXENhcmJvbkJsYWNrXERhdGFGaWxlc1xjZmcuaW5pIEM6XFByb2dyYW1EYXRhXENhcmJvbkJsYWNrXERhdGFGaWxlc1xjZmctYmtwLWU1ZmRmYjgwMWNlYWM3M2I4ZjMyZjFmZWRmNjIxYzE0LmluaQ==": "ICAgICAgICAxIGZpbGUocykgY29waWVkLg0K"
        },
        "2": {
        (...)
    }
  }
}
```

Main Sources: \
https://developer.carbonblack.com \
https://carbon-black-cloud-python-sdk.readthedocs.io \
https://github.com/carbonblack/carbon-black-cloud-sdk-python \
https://github.com/carbonblack/carbon-black-cloud-sdk-python/blob/develop/examples/platform/list_devices.py \
https://stackoverflow.com

Special thanks: \
https://github.com/j3r3mias - Everytime I got stuck in Python shenanigans, you guided me. Thanks bro.
