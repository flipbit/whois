using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Whois.Resources
{
    /// <summary>
    /// Class to read all the embedded WHOIS patterns in an assembly
    /// </summary>
    public class Embedded
    {
        public static Stream RootServerCache => GetStream("Whois.Resources.Cache.RootServerCache.txt");

        public static class Patterns
        {
            public static class Servers
            {
                public static string Iana => GetString("Whois.Resources.Patterns.Servers.Iana.txt");
            }

            public static class Redirects
            {
                public static string VerisignGrs => GetString("Whois.Resources.Patterns.Redirects.VerisignGrs.txt");
            }

            public static class Domains
            {
                public static void ForEach(Action<string, string> action)
                {
                    var names = GetResourceNames("Whois.Resources.Patterns.Domains");

                    foreach (var name in names)
                    {
                        var patternName = name.Replace(".txt", string.Empty);
                        var pattern = GetString(name);

                        action.Invoke(patternName, pattern);
                    }
                }
            }
        }

        private static List<string> GetResourceNames(string @namespace)
        {
            var results = new List<string>();

            var names = typeof(Embedded).Assembly.GetManifestResourceNames();

            foreach (var name in names)
            {
                if (!name.StartsWith(@namespace)) continue;

                if (!name.EndsWith(".txt", StringComparison.InvariantCultureIgnoreCase)) continue;

                results.Add(name);
            }

            return results;
        }

        private static Stream GetStream(string name)
        {
            var assembly = typeof(Embedded).Assembly;

            return assembly.GetManifestResourceStream(name);
        }

        private static string GetString(string name)
        {
            using (var stream = GetStream(name))
            {
                using (var reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }
    }
}