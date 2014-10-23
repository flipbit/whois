using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Whois
{
    /// <summary>
    /// Class to read all the embedded WHOIS patterns in an assembly
    /// </summary>
    public class EmbeddedPatternReader
    {
        /// <summary>
        /// Gets the resource names.
        /// </summary>
        /// <returns></returns>
        public IList<string> GetResourceNames()
        {
            return GetResourceNames(GetType().Assembly, "Whois.Patterns");
        }

        /// <summary>
        /// Gets the resource names.
        /// </summary>
        /// <param name="assembly">The assembly.</param>
        /// <param name="namespace">The namespace.</param>
        /// <returns></returns>
        public IList<string> GetResourceNames(Assembly assembly, string @namespace)
        {
            var results = new List<string>();

            var names = assembly.GetManifestResourceNames();

            foreach (var name in names)
            {
                if (!name.StartsWith(@namespace)) continue;

                if (!name.EndsWith(".txt", StringComparison.InvariantCultureIgnoreCase)) continue;

                results.Add(name);
            }

            return results;
        }

        /// <summary>
        /// Reads the embedded resource in the specified assembly.
        /// </summary>
        /// <param name="assembly">The assembly.</param>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public string Read(Assembly assembly, string name)
        {
            using (var stream = assembly.GetManifestResourceStream(name))
            using (var reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        public IList<string> ReadNamespace(Assembly assembly, string @namespace)
        {
            var results = new List<string>();

            var names = GetResourceNames(assembly, @namespace);

            foreach (var name in names)
            {
                var result = Read(assembly, name);

                if (!string.IsNullOrEmpty(result)) results.Add(result);
            }

            return results;
        }
    }
}