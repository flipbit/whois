using System;
using System.Collections.Generic;
using System.IO;

namespace Whois
{
    /// <summary>
    /// Reads embedded resources in the WHOIS library
    /// </summary>
    public class ResourceReader
    {
        public string GetName(string whoisServer, string tld, string name)
        {
            return $"{GetResourcePrefix(whoisServer, tld)}{name}.txt";
        }

        /// <summary>
        /// Gets the embedded resource names for the given WHOIS server and TLD.
        /// </summary>
        public List<string> GetNames(string whoisServer, string tld)
        {
            var results = new List<string>();

            if (string.IsNullOrEmpty(whoisServer)) return results;
            if (string.IsNullOrEmpty(tld)) return results;

            var names = typeof(ResourceReader).Assembly.GetManifestResourceNames();
            var prefix = GetResourcePrefix(whoisServer, tld);

            foreach (var name in names)
            {
                if (!name.StartsWith(prefix)) continue;

                if (!name.EndsWith(".txt", StringComparison.InvariantCultureIgnoreCase)) continue;

                results.Add(name);
            }

            return results;
        }

        public List<string> GetNames(string whoisServer)
        {
            var results = new List<string>();

            if (string.IsNullOrEmpty(whoisServer)) return results;

            var names = typeof(ResourceReader).Assembly.GetManifestResourceNames();
            var prefix = GetResourcePrefix(whoisServer);

            foreach (var name in names)
            {
                if (!name.StartsWith(prefix)) continue;

                if (!name.EndsWith(".txt", StringComparison.InvariantCultureIgnoreCase)) continue;

                results.Add(name);
            }

            return results;
        }

        public string GetContent(string name)
        {
            return GetString(name);
        }

        private string GetResourcePrefix(string whoisServer, string tld)
        {
            var escapedWhoisServer = whoisServer.Replace("-", "_").ToLowerInvariant();
            var escapedTld = tld.Replace("-", "_").ToLowerInvariant();

            return $"Whois.Resources.{escapedWhoisServer}.{escapedTld}.";
        }

        private string GetResourcePrefix(string whoisServer)
        {
            var escapedWhoisServer = whoisServer.Replace("-", "_").ToLowerInvariant();

            return $"Whois.Resources.{escapedWhoisServer}";
        }

        private static Stream GetStream(string name)
        {
            var assembly = typeof(ResourceReader).Assembly;

            return assembly.GetManifestResourceStream(name);
        }

        private static string GetString(string name)
        {
            using (var stream = GetStream(name))
            {
                if (stream == null) return string.Empty;

                using (var reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }
    }
}
