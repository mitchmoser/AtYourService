using System;
using System.Linq;
using System.Management;
using System.Threading;

namespace AtYourService
{
    class Program
    {
        static void Main(string[] args)
        {
            string[] hosts = { "localhost" };
            // Test if input arguments were supplied
            if (args.Length > 0)
            {
                hosts = args[0].Split(',');
            }

            string ns = @"root\cimv2";
            foreach (string host in hosts)
            {
                Thread newThread = new Thread(() => GetServices(ns, host));
                newThread.Start();
            }
        }
        
        static void GetServices(string ns, string host)
        {
            ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));
            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
            SelectQuery query = new SelectQuery("SELECT name,displayname,startname,description,systemname FROM Win32_Service WHERE startname IS NOT NULL");

            // Requires Local Admin. Try catch for insufficient privs, network connectivity issues, etc
            try
            {
                Console.WriteLine("[+] {0} - Connecting", host);
                scope.Connect();
                //https://stackoverflow.com/questions/842533/in-c-sharp-how-do-i-query-the-list-of-running-services-on-a-windows-server
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    Console.WriteLine("[+] {0} - Enumerating services", host);
                    ManagementObjectCollection services = searcher.Get();
                    Console.WriteLine("[+] {0} - Found {1} services running", host, services.Count);
                    Console.WriteLine("[+] {0} - Filtering out LocalSystem and NT Authority Account services", host);
                    bool results = false;
                    foreach (ManagementObject service in services)
                    {
                        // Exclude services running as local accounts
                        string[] exclusions = { "LOCALSYSTEM", "NT AUTHORITY\\LOCALSERVICE", "NT AUTHORITY\\NETWORKSERVICE" };
                        if (!exclusions.Contains(service["StartName"].ToString().ToUpper()))
                        {
                            Console.WriteLine("[+] Host: {0}", service["SystemName"]);
                            Console.WriteLine(" Account: {0}", service["StartName"]);
                            Console.WriteLine(" Service: {0}", service["Name"]);
                            Console.WriteLine("    Name: {0}", service["DisplayName"]);
                            Console.WriteLine("    Info: {0}", service["Description"]);
                            results = true;
                        }
                    }
                    if (!results)
                    {
                        Console.WriteLine("[!] {0} - No other services identified", host);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] " + ex.Message);
                Console.WriteLine("[!] {0} - Unable to query services", host);
            }
        }
    }
}
