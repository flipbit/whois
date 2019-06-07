using System;
using System.Linq;
using Whois.Models;

namespace Whois
{
    /// <summary>
    /// Helper to bootstrap template assertions
    /// </summary>
    public class AssertWriter
    {
        public static void Write(ParsedWhoisResponse response)
        {
            Write(nameof(response.FieldsParsed), response.FieldsParsed);
            Write(nameof(response.ParsingErrors), response.ParsingErrors);

            Console.WriteLine();

            Write(nameof(response.DomainName), response.DomainName);
            Write(nameof(response.RegistryDomainId), response.RegistryDomainId);

            Console.WriteLine();

            Write(nameof(response.Registrar) + "." + nameof(response.Registrar.Name), response.Registrar?.Name);
            Write(nameof(response.Registrar) + "." + nameof(response.Registrar.Url), response.Registrar?.Url);
            Write(nameof(response.Registrar) + "." + nameof(response.Registrar.WhoisServerUrl), response.Registrar?.WhoisServerUrl);
            Write(nameof(response.Registrar) + "." + nameof(response.Registrar.AbuseEmail), response.Registrar?.AbuseEmail);
            Write(nameof(response.Registrar) + "." + nameof(response.Registrar.AbuseTelephoneNumber), response.Registrar?.AbuseTelephoneNumber);

            Console.WriteLine();

            Write(nameof(response.Updated), response.Updated);
            Write(nameof(response.Registered), response.Registered);
            Write(nameof(response.Expiration), response.Expiration);

            Write(nameof(response.Registrant), response.Registrant);
            Write(nameof(response.AdminContact), response.AdminContact);
            Write(nameof(response.BillingContact), response.BillingContact);
            Write(nameof(response.TechnicalContact), response.TechnicalContact);

            Console.WriteLine();

            if (response.NameServers.Any())
            {
                Write($"{nameof(response.NameServers)}.Count", response.NameServers.Count);

                for (var i = 0; i < response.NameServers.Count; i++)
                {
                    var nameServer = response.NameServers[i];

                    Write($"{nameof(response.NameServers)}[{i}]", nameServer);
                }
                Console.WriteLine();
            }

            if (response.DomainStatus.Any())
            {
                Write($"{nameof(response.DomainStatus)}.Count", response.DomainStatus.Count);

                for (var i = 0; i < response.DomainStatus.Count; i++)
                {
                    var status = response.DomainStatus[i];

                    Write($"{nameof(response.DomainStatus)}[{i}]", status);
                }
                Console.WriteLine();
            }

            Write(nameof(response.DnsSecStatus), response.DnsSecStatus);
        }

        private static void Write(string prefix, Contact contact)
        {
            if (contact == null) return;

            Write($"{prefix}.{nameof(Contact.RegistryId)}", contact.RegistryId);
            Write($"{prefix}.{nameof(Contact.Name)}", contact.Name);
            Write($"{prefix}.{nameof(Contact.Organization)}", contact.Organization);

            if (contact.Address.Any())
            {
                Console.WriteLine();
                Write($"{prefix}.{nameof(Contact.Address)}.Count", contact.Address.Count);

                for (var i = 0; i < contact.Address.Count; i++)
                {
                    var address = contact.Address[i];

                    Write($"{prefix}.{nameof(Contact.Address)}[{i}]", address);
                }
                Console.WriteLine();
            }

            Write($"{prefix}.{nameof(Contact.TelephoneNumber)}", contact.TelephoneNumber);
            Write($"{prefix}.{nameof(Contact.TelephoneNumberExt)}", contact.TelephoneNumberExt);
            Write($"{prefix}.{nameof(Contact.FaxNumber)}", contact.FaxNumber);
            Write($"{prefix}.{nameof(Contact.FaxNumberExt)}", contact.FaxNumberExt);
            Write($"{prefix}.{nameof(Contact.Email)}", contact.Email);

            Console.WriteLine();
        }

        private static void Write(string fieldName, string expectedValue)
        {
            if (string.IsNullOrEmpty(expectedValue)) return;

            Console.WriteLine($@"            Assert.AreEqual(""{expectedValue}"", response.{fieldName});");
        }

        private static void Write(string fieldName, int expectedValue)
        {
            Console.WriteLine($@"            Assert.AreEqual({expectedValue}, response.{fieldName});");
        }

        private static void Write(string fieldName, DateTime? expectedValue)
        {
            if (expectedValue.HasValue == false) return;

            Console.WriteLine($@"            Assert.AreEqual(new DateTime({expectedValue.Value.Year}, {expectedValue.Value.Month}, {expectedValue.Value.Day}, {expectedValue.Value.Hour}, {expectedValue.Value.Minute}, {expectedValue.Value.Second}), response.{fieldName});");
        }
    }
}
