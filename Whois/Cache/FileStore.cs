using System;
using System.Collections.Generic;
using System.IO;
using Whois.Extensions;

namespace Whois.Cache
{
    /// <summary>
    /// Class to wrap access to the file system
    /// </summary>
    public class FileStore : IFileStore
    {
        public string BaseFolderPath
        {
            get
            {
                var result = @"c:\whois";

                var cachePath = Environment.GetEnvironmentVariable("WHOIS_CACHE_PATH");

                if (!string.IsNullOrEmpty(cachePath) && Directory.Exists(cachePath))
                {
                    result = cachePath;
                }

                return result;
            }
        }

        public string GetFileName(string area, string key)
        {
            return Path.Combine(BaseFolderPath, area, key + ".txt");
        }

        /// <summary>
        /// Writes the specified string to the key in the given area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        /// <exception cref="NotImplementedException"></exception>
        public void Write(string area, string key, string value)
        {
            File.WriteAllText(GetFileName(area, key), value);
        }

        /// <summary>
        /// Reads the value of the given key from the specified area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public string Read(string area, string key)
        {
            var result = string.Empty;

            if (Exists(area, key))
            {
                result = File.ReadAllText(GetFileName(area, key));
            }

            return result;
        }

        /// <summary>
        /// Reads the value of the given key from the specified area.  Returns empty if
        /// the value was not written within the last <see cref="maxAgeMinutes" />.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <param name="maxAgeMinutes">The maximum age minutes.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public string Read(string area, string key, int maxAgeMinutes)
        {
            var result = string.Empty;

            if (Exists(area, key, maxAgeMinutes))
            {
                result = Read(area, key);
            }

            return result;
        }

        /// <summary>
        /// Determines if the specified key exists in the specified area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public bool Exists(string area, string key)
        {
            return File.Exists(GetFileName(area, key));
        }

        /// <summary>
        /// Determines if the specified key exists in the specified area.  The key must have
        /// been written to within the value specified in <see cref="maxAgeMinutes" />.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <param name="maxAgeMinutes">The maximum age minutes.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public bool Exists(string area, string key, int maxAgeMinutes)
        {
            var result = false;

            if (Exists(area, key))
            {
                var writeTime = File.GetLastWriteTime(GetFileName(area, key));

                result = writeTime.AddMinutes(maxAgeMinutes) > DateTime.Now;
            }

            return result;
        }

        /// <summary>
        /// Gets the keys that exist in the specified area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public IList<string> GetKeys(string area)
        {
            var results = new List<string>();
            var fileName = GetFileName(area, "dummy");
            var path = Path.GetDirectoryName(fileName);

            var files = Directory.GetFiles(path);

            foreach (var file in files)
            {
                results.Add(Path.GetFileName(file).ToLower().SubstringBeforeChar("."));
            }

            return results;
        }

        /// <summary>
        /// Gets the date and time that the given key was last written to.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public DateTime GetWriteDateTime(string area, string key)
        {
            return File.GetLastWriteTime(GetFileName(area, key));
        }
    }
}
