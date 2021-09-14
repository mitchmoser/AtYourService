# AtYourService
C# .NET Assembly and python script for Service Enumeration 

Queries all services on a host and filters out services running as `LocalSystem`, `NT Authority\LocalService`, and `NT Authority\NetworkService`

Requires Local Administrator Privileges on target machine

## C# .NET Assembly
Uses the [Win32_Service Class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service) which wraps the WMI provider `Win32_BaseService`

If no hostname is specified, localhost will be enumerated

Multiple hostnames can be provided separated by commas

### Example Usage
```
execute-assembly /opt/SharpTools/AtYourService.exe WEB01.contoso.com,DEV02.contoso.com
```
### Output
```
[*] Tasked beacon to run .NET program: AtYourService.exe WEB01.contoso.com,DEV02.contoso.com
[+] host called home, sent: 111705 bytes
[+] received Output
[+] WEB01.contoso.com - Connecting
[+] DEV02.contoso.com - Connecting
[+] WEB01.contoso.com - Enumerating services
[+] DEV02.contoso.com - Enumerating services
[+] WEB01.contoso.com - Found 213 services running
[+] DEV02.contoso.com - Found 144 services running
[+] WEB01.contoso.com - Filtering out LocalSystem and NT Authority Account services
[+] DEV02.contoso.com - Filtering out LocalSystem and NT Authority Account services
[+] Host: WEB01
 Account: contoso.com\ServerAdmin
 Service: examplesvc
    Name: Example Service
    Info: Example Service runs on web servers
[!] DEV02.contoso.com - No other services identified
```

## Python
Built upon [Impacket's](https://github.com/SecureAuthCorp/impacket) [`wmiquery.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiquery.py) and requires Impacket to be installed on host.

Place `AtYourService.py` in the `impacket/examples/` directory

### Example Usage
```
python3 /usr/share/doc/python3-impacket/examples/AtYourService.py contoso/Bob@10.0.0.1,10.0.0.2,10.0.0.3
```
Specifying additional targets by comma separation
### Output
```
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[+] Enumerating services on 10.0.0.1, 10.0.0.2, 10.0.0.3
[+] Connected to 10.10.0.1
[+] Finished querying 10.10.0.1
[+] Found 205 services running...
[+] Filtering out LocalSystem nd NT Authority Account services...
[!] No other services identified on 10.0.0.1
[+] Connected to 10.0.0.2
[+] Finished querying 10.0.0.2
[+] Found 202 services running...
[+] Filtering out LocalSystem nd NT Authority Account services...
[+]        Service: examplesvc
              Name: Example Service
           Account: ServerAdmin@contoso.com
       Description: Example Service runs on web servers
            System: WEB01
[+] Connected to 10.0.0.3
[+] Finished querying 10.0.0.3
[+] Found 184 services running...
[+] Filtering out LocalSystem nd NT Authority Account services...
[!] No other services identified on 10.0.0.3
```
