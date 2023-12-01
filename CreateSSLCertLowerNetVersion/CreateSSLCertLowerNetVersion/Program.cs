using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace CreateSSLCertLowerNetVersion
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var keepRunning = true;

                while (keepRunning)
                {
                    keepRunning = Run();
                }

                // Close
                Console.WriteLine("Press enter or close this window...");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }

        }

        static bool Run()
        {
            // Ask user to enter in common names
            string names = "";
            while (names == "")
            {
                Console.WriteLine("Please enter a delimited list of cert names:   ");
                names = Console.ReadLine();
                if (names == "")
                    Console.WriteLine("The list cannot be empty");
            }

            // Ask user what the delimeter is 
            string delim = "";
            while (delim == "")
            {
                Console.WriteLine("\nPlease enter the delimiter for the list of names:   ");
                delim = Console.ReadLine();
                if (delim == "")
                    Console.WriteLine("The delimiter cannot be empty");
            }


            try
            {
                // Split the user list by the defined delimeter
                var nameArray = names.Split(delim).ToList();

                // Remove spaces from name
                nameArray = nameArray.Select(x => x.Replace(" ", "")).ToList();

                // Remove duplicates
                nameArray = RemoveDuplicatesfromUserDefinedList(nameArray);

                // Remove duplicates from store
                RemoveDuplicatesfromStore(nameArray);

                // Loop through the list and create certs for each
                foreach (var name in nameArray)
                {
                    // Make sure value is not blank
                    if (name != "")
                        // Create and enroll the certs
                        CreateandEnrollCert(name);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"List issue: {ex.Message}");

            }

            // Ask user if they want to enter in more
            string more = "";
            while (more == "")
            {
                Console.WriteLine("Would you like to enter more certs (y/n)?   ");
                more = Console.ReadLine().ToLower();
                if (more == "y")
                    return true;
                else if (more == "n")
                    return false;
                else
                    Console.WriteLine("Incorrect input");
            }

            return false;
        }

        static List<string> RemoveDuplicatesfromUserDefinedList(List<string> nameArray)
        {
            // Get duplicates
            var query = nameArray.GroupBy(x => x)
                              .Where(g => g.Count() > 1)
                              .Select(y => y.Key)
                              .ToList();

            // Alert user of duplicate values
            foreach (var item in query)
            {
                Console.WriteLine($"\nDuplicate Value: {item}\n");
            }

            // Return the list with only distinct values (one occurance of each value)
            return nameArray.Distinct().ToList();
        }

        static List<string> RemoveDuplicatesfromStore(List<string> nameArray)
        {
            // Create the store for the local machine certs
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            // Open the store with read/write permissions
            store.Open(OpenFlags.ReadWrite);

            // Loop through store certs and remove certs with names matching the user entered list
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                // Check if store cert has same name as user entered names
                if (nameArray.Contains(certificate.FriendlyName))
                {
                    try
                    {
                        store.Remove(certificate);
                        Console.WriteLine($"Certificate Removed: {certificate.FriendlyName}");
                    }
                    catch (Exception ex)
                    {
                        nameArray.Remove(certificate.FriendlyName);
                        Console.WriteLine($"Unable to remove cert {certificate.FriendlyName}. Removing from user entered list. Error: {ex.Message}");
                    }

                }
            }

            // Close the store
            store.Close();

            return nameArray;
        }

        static void CreateandEnrollCert(string commonName, string templateName = "WebServer")
        {
            // Create certificate request and enrollment variable
            CX509CertificateRequestPkcs10 request = new CX509CertificateRequestPkcs10();
            CX509Enrollment enrollment = new CX509Enrollment();

            try
            {
                // Initialize the certificate request object
                request.InitializeFromTemplateName(X509CertificateEnrollmentContext.ContextMachine, templateName);

                // Set the certificate subject name
                request.Subject = new CX500DistinguishedName();
                request.Subject.Encode($"CN={commonName}", X500NameFlags.XCN_CERT_NAME_STR_NONE);

                // Set alternate dns names
                request.X509Extensions.Add((CX509Extension)SetAlternateDNSNames(commonName));

                // Make private key exportable
                request.PrivateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;

                // Create the certificate request
                var requestString = request.GetInnerRequest(InnerRequestLevel.LevelInnermost);

                // Initialize the Enrollment object with the certificate request
                enrollment.InitializeFromRequest(requestString);

                // Set friendly name
                enrollment.CertificateFriendlyName = commonName;

                // Submit the certificate request to the certification authority (CA)
                enrollment.Enroll();

                // Let user know the certificate was created
                Console.WriteLine($"\nCertificate issued: {commonName}.");

                // Export the private key along with the certificate
                ExportCertwithKey(enrollment, commonName);
            }
            catch (Exception ex)
            {
                // Handle any errors that occurred during the certificate enrollment process
                Console.WriteLine($"\nCertificate enrollment failed: {ex.Message} \n");
            }
        }

        static CX509ExtensionAlternativeNames SetAlternateDNSNames(string commonName)
        {
            // Create and configure the DNS alternative names extension
            CX509ExtensionAlternativeNames dnsExtensionAlternativeNames = new CX509ExtensionAlternativeNames();
            CAlternativeNames dnsAlternativeNames = new CAlternativeNames();
            CAlternativeName dnsAlternativeName = new CAlternativeName();
            CAlternativeName dnsAlternativeName2 = new CAlternativeName();

            // Add commonName to dns alternative
            dnsAlternativeName.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, commonName);
            dnsAlternativeNames.Add(dnsAlternativeName);
            // Add www. to dns alternative
            dnsAlternativeName2.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, $"www.{commonName}");
            dnsAlternativeNames.Add(dnsAlternativeName2);

            // Add the DNS alternative names extension to the certificate request
            dnsExtensionAlternativeNames.InitializeEncode(dnsAlternativeNames);

            return dnsExtensionAlternativeNames;
        }

        static void ExportCertwithKey(CX509Enrollment enrollment, string commonName)
        {
            try
            {
                var exportedCertificate = new X509Certificate2(Convert.FromBase64String(enrollment.Certificate));

                // Export the certificate with the private key using a password
                byte[] pfxBytes = Convert.FromBase64String(enrollment.CreatePFX("Password.123", PFXExportOptions.PFXExportChainWithRoot));

                // Save the PFX file to disk
                File.WriteAllBytes($@"{Environment.GetFolderPath(Environment.SpecialFolder.Desktop)}\{commonName}.pfx", pfxBytes);

                Console.WriteLine("Certificate with private key exported successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Certificate with private key failed to export: {ex.Message}");
            }
        }
    }
}
