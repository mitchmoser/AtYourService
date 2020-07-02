#!/usr/bin/python3
# Modified from and designed to work within Impacket by
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: [MS-WMI] example. It allows to issue WQL queries and
#              get description of the objects.
#
#              e.g.: select name from win32_account
#              e.g.: describe win32_process
# 
# Author:
#  Mitchell Moser
#
# Reference for:
#  DCOM
#
from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY

if __name__ == '__main__':
    import cmd

    class WMIQUERY(cmd.Cmd):
        def __init__(self, iWbemServices):
            cmd.Cmd.__init__(self)
            self.iWbemServices = iWbemServices

        def printReply(self, iEnum):
            exclusions = ["LOCALSYSTEM", "NT AUTHORITY\\LOCALSERVICE", "NT AUTHORITY\\NETWORKSERVICE"]
            counter = 0
            services = []
            print("[+] Connected to %s" % address)
            while True:
                try:
                    pEnum = iEnum.Next(0xffffffff,1)[0]
                    record = pEnum.getProperties()
                    account = record['StartName']['value']
                    name = record['DisplayName']['value']
                    service = record['Name']['value']
                    description = record['Description']['value']
                    system = record['SystemName']['value']
                    counter += 1
                    if account.upper() not in exclusions:
                        newEntry = {'Account': account, 'Name': name, 'Service': service, 'Description': description, 'System': system}
                        services.append(newEntry)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    if str(e).find('S_FALSE') < 0:
                        raise
                    else:
                        print("[+] Finished querying host")
                        break
            print("[+] Found %d services running..." % counter)
            print("[+] Filtering out LocalSystem and NT Authority Account services...")
            if len(services) == 0:
                print("[!] No other services identified on %s" % address)
            for i in range(0, len(services)):
                print("[+] %14s: %s" % ("Service", services[i]['Service']))
                print("%18s: %s" % ("Name", services[i]['Name']))
                print("%18s: %s" % ("Account", services[i]['Account']))
                print("%18s: %s" % ("Description", services[i]['Description']))
                print("%18s: %s" % ("System", services[i]['System']))
            iEnum.RemRelease()

        def default(self, line):
            line = line.strip('\n')
            if line[-1:] == ';':
                line = line[:-1]
            try:
                iEnumWbemClassObject = self.iWbemServices.ExecQuery(line.strip('\n'))
                self.printReply(iEnumWbemClassObject)
                iEnumWbemClassObject.RemRelease()
            except Exception as e:
                logging.error(str(e))

        def emptyline(self):
            pass

        def do_exit(self, line):
            return True

    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Queries all services on a host using Windows Management Instrumentation. " +
                                                                    "\nFilters out services running as LocalSystem, NT Authority\\LocalService, and NT Authority\\NetworkService")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-namespace', action='store', default='//./root/cimv2', help='namespace name (default //./root/cimv2)')
    parser.add_argument('-hosts', action='store', help='specify additional hosts to enumerate separated by comma')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-rpc-auth-level', choices=['integrity', 'privacy','default'], nargs='?', default='default',
                       help='default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy '
                            '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require '
                            'privacy level by default)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    hosts = []

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')
    hosts.append(address)

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if options.hosts is not None:
        for host in options.hosts.split(','):
            hosts.append(host)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    print("[+] Enumerating services on %s" % ", ".join([str(x) for x in hosts]))
    for address in hosts:
        try:
            dcom = DCOMConnection(address, username, password, domain, lmhash, nthash, options.aesKey, oxidResolver=True,
                                  doKerberos=options.k, kdcHost=options.dc_ip)

            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin(options.namespace, NULL, NULL)
            if options.rpc_auth_level == 'privacy':
                iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            elif options.rpc_auth_level == 'integrity':
                iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

            iWbemLevel1Login.RemRelease()

            shell = WMIQUERY(iWbemServices)
            line = "SELECT name,displayname,startname,description,systemname FROM Win32_Service WHERE startname IS NOT NULL"
            shell.onecmd(line)

            iWbemServices.RemRelease()
            dcom.disconnect()
        except Exception as e:
            logging.error(str(e))
            try:
                dcom.disconnect()
            except:
                pass
