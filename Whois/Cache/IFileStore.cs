using System;
using System.Collections.Generic;

namespace Whois.Cache
{
    /// <summary>
    /// Wrapper for accessing the file system
    /// </summary>
    public interface IFileStore
    {
        /// <summary>
        /// Writes the specified string to the key in the given area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        void Write(string area, string key, string value);

        /// <summary>
        /// Reads the value of the given key from the specified area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        string Read(string area, string key);

        /// <summary>
        /// Reads the value of the given key from the specified area.  Returns empty if
        /// the value was not written within the last <see cref="maxAgeMinutes"/>.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <param name="maxAgeMinutes">The maximum age minutes.</param>
        /// <returns></returns>
        string Read(string area, string key, int maxAgeMinutes);

        /// <summary>
        /// Determines if the specified key exists in the specified area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        bool Exists(string area, string key);

        /// <summary>
        /// Determines if the specified key exists in the specified area.  The key must have
        /// been written to within the value specified in <see cref="maxAgeMinutes"/>.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <param name="maxAgeMinutes">The maximum age minutes.</param>
        /// <returns></returns>
        bool Exists(string area, string key, int maxAgeMinutes);

        /// <summary>
        /// Gets the keys that exist in the specified area.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <returns></returns>
        IList<string> GetKeys(string area);

        /// <summary>
        /// Gets the date and time that the given key was last written to.
        /// </summary>
        /// <param name="area">The area.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        DateTime GetWriteDateTime(string area, string key);
    }
}
