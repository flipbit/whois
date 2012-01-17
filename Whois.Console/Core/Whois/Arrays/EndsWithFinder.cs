using System;

namespace Flipbit.Core.Whois.Arrays
{
    /// <summary>
    /// Finder class that matches a string if it ends with the given query
    /// </summary>
    public class EndsWithFinder : ArrayFinder
    {
        /// <summary>
        /// Determines if a specified line matches the given query
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="query">The query.</param>
        /// <returns></returns>
        public override bool Match(string value, string query)
        {
            return value.Trim().EndsWith(query, StringComparison.InvariantCultureIgnoreCase);
        }
    }
}