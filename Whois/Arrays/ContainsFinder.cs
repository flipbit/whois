using System;

namespace Whois.Arrays
{
    /// <summary>
    /// Finder class that matches a string if it contains the given query
    /// </summary>
    public class ContainsFinder : ArrayFinder
    {
        /// <summary>
        /// Determines if a specified line matches the given query
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="query">The query.</param>
        /// <returns></returns>
        public override bool Match(string value, string query)        
        {
            return value.IndexOf(query, StringComparison.InvariantCultureIgnoreCase) > -1;
        }
    }
}