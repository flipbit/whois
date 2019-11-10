using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Whois
{
    /// <summary>
    /// Helper to bootstrap template assertions
    /// </summary>
    public class AssertWriter
    {
        private static StringBuilder sb = new StringBuilder();

        public static void Write(WhoisResponse response)
        {
            sb.Clear();

            Write(nameof(response.ParsingErrors), response.ParsingErrors);
            Write(nameof(response.TemplateName), response.TemplateName);

            sb.AppendLine();

            Write(nameof(response.DomainName), response.DomainName);
            Write(nameof(response.RegistryDomainId), response.RegistryDomainId);

            if (response.Registrar != null)
            {
                sb.AppendLine();
                sb.AppendLine("            // Registrar Details");

                Write(nameof(response.Registrar) + "." + nameof(response.Registrar.Name), response.Registrar?.Name);
                Write(nameof(response.Registrar) + "." + nameof(response.Registrar.IanaId), response.Registrar?.IanaId);
                Write(nameof(response.Registrar) + "." + nameof(response.Registrar.Url), response.Registrar?.Url);
                Write(nameof(response.Registrar) + "." + nameof(response.Registrar.WhoisServer.Value), response.Registrar?.WhoisServer);
                Write(nameof(response.Registrar) + "." + nameof(response.Registrar.AbuseEmail), response.Registrar?.AbuseEmail);
                Write(nameof(response.Registrar) + "." + nameof(response.Registrar.AbuseTelephoneNumber), response.Registrar?.AbuseTelephoneNumber);
            }

            sb.AppendLine();

            Write(nameof(response.Updated), response.Updated);
            Write(nameof(response.Registered), response.Registered);
            Write(nameof(response.Expiration), response.Expiration);

            Write(nameof(response.Registrant), response.Registrant);
            Write(nameof(response.AdminContact), response.AdminContact);
            Write(nameof(response.BillingContact), response.BillingContact);
            Write(nameof(response.TechnicalContact), response.TechnicalContact);
            Write(nameof(response.ZoneContact), response.ZoneContact);

            sb.AppendLine();

            if (response.NameServers.Any())
            {
                sb.AppendLine("            // Nameservers");
                Write($"{nameof(response.NameServers)}.Count", response.NameServers.Count);

                for (var i = 0; i < response.NameServers.Count; i++)
                {
                    var nameServer = response.NameServers[i];

                    Write($"{nameof(response.NameServers)}[{i}]", nameServer);
                }
                sb.AppendLine();
            }

            if (response.DomainStatus.Any())
            {
                sb.AppendLine("            // Domain Status");
                Write($"{nameof(response.DomainStatus)}.Count", response.DomainStatus.Count);

                for (var i = 0; i < response.DomainStatus.Count; i++)
                {
                    var status = response.DomainStatus[i];

                    Write($"{nameof(response.DomainStatus)}[{i}]", status);
                }
                sb.AppendLine();
            }

            Write(nameof(response.DnsSecStatus), response.DnsSecStatus);
            
            Write(nameof(response.FieldsParsed), response.FieldsParsed);

            Console.WriteLine(sb.ToString());
            WindowsClipboard.SetText(sb.ToString());
        }

        private static void Write(string prefix, Contact contact)
        {
            if (contact == null) return;

            sb.AppendLine();
            sb.AppendLine($"             // {prefix} Details");
            Write($"{prefix}.{nameof(Contact.RegistryId)}", contact.RegistryId);
            Write($"{prefix}.{nameof(Contact.Name)}", contact.Name);
            Write($"{prefix}.{nameof(Contact.Organization)}", contact.Organization);
            Write($"{prefix}.{nameof(Contact.TelephoneNumber)}", contact.TelephoneNumber);
            Write($"{prefix}.{nameof(Contact.TelephoneNumberExt)}", contact.TelephoneNumberExt);
            Write($"{prefix}.{nameof(Contact.FaxNumber)}", contact.FaxNumber);
            Write($"{prefix}.{nameof(Contact.FaxNumberExt)}", contact.FaxNumberExt);
            Write($"{prefix}.{nameof(Contact.Email)}", contact.Email);
            Write($"{prefix}.{nameof(Contact.Created)}", contact.Created);
            Write($"{prefix}.{nameof(Contact.Updated)}", contact.Updated);

            if (contact.Address.Any())
            {
                sb.AppendLine();
                sb.AppendLine($"             // {prefix} Address");
                Write($"{prefix}.{nameof(Contact.Address)}.Count", contact.Address.Count);

                for (var i = 0; i < contact.Address.Count; i++)
                {
                    var address = contact.Address[i];

                    Write($"{prefix}.{nameof(Contact.Address)}[{i}]", address);
                }
            }

            sb.AppendLine();
        }

        private static void Write(string fieldName, HostName expectedValue)
        {
            if (expectedValue == null) return;

            if (string.IsNullOrEmpty(expectedValue.ToString()) == false)
            {
                Write($"{fieldName}.ToString()", expectedValue.ToString());
            }

            if (string.IsNullOrEmpty(expectedValue.ToUnicodeString()) == false && expectedValue.IsPunyCode)
            {
                Write($"{fieldName}.ToUnicodeString()", expectedValue.ToString());
            }
        }

        private static void Write(string fieldName, string expectedValue)
        {
            if (string.IsNullOrEmpty(expectedValue)) return;

            if (expectedValue.Contains("\""))
            {
                sb.AppendLine($@"            Assert.AreEqual(@""{expectedValue.Replace("\"", "\"\"")}"", response.{fieldName});");
            }
            else
            {
                sb.AppendLine($@"            Assert.AreEqual(""{expectedValue}"", response.{fieldName});");
            }

        }

        private static void Write(string fieldName, int expectedValue)
        {
            sb.AppendLine($@"            Assert.AreEqual({expectedValue}, response.{fieldName});");
        }

        private static void Write(string fieldName, DateTime? expectedValue)
        {
            if (expectedValue.HasValue == false) return;

            sb.AppendLine($@"            Assert.AreEqual(new DateTime({expectedValue.Value.Year}, {expectedValue.Value.Month:00}, {expectedValue.Value.Day:00}, {expectedValue.Value.Hour:00}, {expectedValue.Value.Minute:00}, {expectedValue.Value.Second:00}, {expectedValue.Value.Millisecond:000}, DateTimeKind.Utc), response.{fieldName});");
        }
    }
}
