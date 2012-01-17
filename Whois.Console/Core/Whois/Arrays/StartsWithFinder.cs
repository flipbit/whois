using System;

namespace Flipbit.Core.Whois.Arrays
{
    /// <summary>
    /// Finds values in array lists that start with the specified value.
    /// </summary>
    class StartsWithFinder : ArrayFinder
    {
        /// <summary>
        /// Determines if a specified line matches the given query
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="query">The query.</param>
        /// <returns></returns>
        public override bool Match(string value, string query)
        {
            return value.Trim().StartsWith(query, StringComparison.CurrentCultureIgnoreCase);
        }
    }
}