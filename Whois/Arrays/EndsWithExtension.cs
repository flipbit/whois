using System.Collections;

namespace Whois.Arrays
{
    /// <summary>
    /// Extension Methods to find lines of an <see cref="ArrayList"/> ending with a specific value.
    /// </summary>
    public static class EndsWithExtension
    {
        private static readonly EndsWithFinder Finder = new EndsWithFinder();

        /// <summary>
        /// Returns the first line on an <see cref="ArrayList"/> ending with the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string EndsWith(this ArrayList array, string value)
        {
            return Finder.FindValue(array, value);
        }

        /// <summary>
        /// Returns the line on an <see cref="ArrayList"/> ending with the specified <see cref="value"/>
        /// starting at <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public static string EndsWith(this ArrayList array, string value, int startIndex)
        {
            return Finder.FindValue(array, value, startIndex);
        }

        /// <summary>
        /// Returns the index of the first line on an <see cref="ArrayList"/> ending with the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static int IndexOfLineEndingWith(this ArrayList array, string value)
        {
            return Finder.FindIndexOfValue(array, value);
        }

        /// <summary>
        /// Returns the index of the line on an <see cref="ArrayList"/> ending with the specified <see cref="value"/>.
        /// starting at <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public static int IndexOfLineEndingWith(this ArrayList array, string value, int startIndex)
        {
            return Finder.FindIndexOfValue(array, value, startIndex);
        }
    }
}