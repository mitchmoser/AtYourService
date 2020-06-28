# AtYourService
C# .NET Assembly for Service Enumeration 

Uses the [Win32_Service Class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service) which wraps the WMI provider `Win32_BaseService` to query all services on a host and filters out services running as `LocalSystem`, `NT Authority\LocalService`, and `NT Authority\NetworkService`.

Requires Local Administrator Privileges on target machine

If no hostname is specified, localhost will be enumerated

Multiple hostnames can be provided separated by commas

## Example Usage
```
execute-assembly /opt/SharpTools/AtYourService.exe WEB01.contoso.com,DEV02.contoso.com
```
### Output
```
[*] Tasked beacon to run .NET program: AtYourService.exe WEB01.contoso.com,DEV02.contoso.com
[+] host called home, sent: 111705 bytes
[+] received Output
[+] Connecting to WEB01.contoso.com
[+] Enumerating services...
[+] Found 213 services running...
[+] Filtering out LocalSystem and NT Authority Account services...
        [+] Service:     examplesvc
            Name:        Example Service
            Account:     contoso.com\ServerAdmin
            Description: Example Service runs on web servers
            System:      WEB01
[+] Connecting to DEV02.contoso.com
[+] Enumerating services...
[+] Found 144 services running...
[+] Filtering out LocalSystem and NT Authority Account services...
[!] No other services identified on DEV02.contoso.com
[+] Finished
```
