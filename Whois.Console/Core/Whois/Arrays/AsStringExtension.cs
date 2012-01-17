using System.Collections;
using System.Text;

namespace Flipbit.Core.Whois.Arrays
{
    /// <summary>
    /// Extension Method to convert an <see cref="ArrayList"/> to a <see cref="string"/>.
    /// </summary>
    public static class AsStringExtension
    {
        /// <summary>
        /// Converts the array list to a string
        /// </summary>
        /// <param name="array">The array.</param>
        /// <returns></returns>
        public static string AsString(this ArrayList array)
        {
            var sb = new StringBuilder();

            foreach(string line in array)
            {
                sb.AppendLine(line);
            }

            return sb.ToString();
        }
    }
}