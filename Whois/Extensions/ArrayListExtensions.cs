using System;
using System.Collections;
using System.Text;

namespace Whois.Extensions 
{
    /// <summary>
    /// Extension methods for <see cref="ArrayList"/> objects.
    /// </summary>
    public static class ArrayListExtensions 
    {
        /// <summary>
        /// Finds values in <see cref="ArrayList"/>s.
        /// </summary>
        private abstract class ArrayFinder {
            /// <summary>
            /// Finds the first instance of the value in the array.
            /// </summary>
            /// <param name="array">The array.</param>
            /// <param name="value">The value.</param>
            /// <returns></returns>
            public string FindValue(ArrayList array, string value) {
                return FindValue(array, value, 0);
            }

            /// <summary>
            /// Finds the instance of the value in the array starting at <see cref="startIndex"/>.
            /// </summary>
            /// <param name="array">The array.</param>
            /// <param name="value">The value.</param>
            /// <param name="startIndex">The start index.</param>
            /// <returns></returns>
            public string FindValue(ArrayList array, string value, int startIndex) {
                var result = string.Empty;

                var index = FindIndexOfValue(array, value, startIndex);

                if (index > -1) {
                    result = array[index].ToString();
                }

                return result;
            }

            /// <summary>
            /// Finds the first index of the value in the array.
            /// </summary>
            /// <param name="array">The array.</param>
            /// <param name="value">The value.</param>
            /// <returns></returns>
            public int FindIndexOfValue(ArrayList array, string value) {
                return FindIndexOfValue(array, value, 0);
            }

            /// <summary>
            /// Finds the index of the value in the array starting as <see cref="startIndex"/>.
            /// </summary>
            /// <param name="array">The array.</param>
            /// <param name="value">The value.</param>
            /// <param name="startIndex">The start index.</param>
            /// <returns></returns>
            public int FindIndexOfValue(ArrayList array, string value, int startIndex) {
                var result = -1;

                for (var i = startIndex; i <= array.Count - 1; i++) {
                    if (!Match(array[i].ToString(), value)) continue;

                    result = i;

                    break;
                }

                return result;
            }

            /// <summary>
            /// Determines if a specified line matches the given query
            /// </summary>
            /// <param name="value">The value.</param>
            /// <param name="query">The query.</param>
            /// <returns></returns>
            public abstract bool Match(string value, string query);
        }

        /// <summary>
        /// Converts the array list to a string
        /// </summary>
        /// <param name="array">The array.</param>
        /// <returns></returns>
        public static string AsString(this ArrayList array) {
            var sb = new StringBuilder();

            foreach (string line in array) {
                sb.AppendLine(line);
            }

            return sb.ToString();
        }

        /// <summary>
        /// Finder class that matches a string if it contains the given query
        /// </summary>
        private class ContainsFinder : ArrayFinder {
            /// <summary>
            /// Determines if a specified line matches the given query
            /// </summary>
            /// <param name="value">The value.</param>
            /// <param name="query">The query.</param>
            /// <returns></returns>
            public override bool Match(string value, string query) {
                return value.IndexOf(query, StringComparison.InvariantCultureIgnoreCase) > -1;
            }
        }

        private static readonly ContainsFinder containsFinder = new ContainsFinder();

        /// <summary>
        /// Returns the first line on an <see cref="ArrayList"/> containing the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string Containing(this ArrayList array, string value) 
        {
            return containsFinder.FindValue(array, value);
        }

        /// <summary>
        /// Returns the line on an <see cref="ArrayList"/> containing the specified <see cref="value"/>
        /// starting at <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public static string Containing(this ArrayList array, string value, int startIndex) 
        {
            return containsFinder.FindValue(array, value, startIndex);
        }

        /// <summary>
        /// Returns the index of the first line on an <see cref="ArrayList"/> containing the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static int IndexOfLineContaining(this ArrayList array, string value) 
        {
            return containsFinder.FindIndexOfValue(array, value);
        }

        /// <summary>
        /// Returns the index of the line on an <see cref="ArrayList"/> containing the specified <see cref="value"/>.
        /// starting at <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public static int IndexOfLineContaining(this ArrayList array, string value, int startIndex) 
        {
            return containsFinder.FindIndexOfValue(array, value, startIndex);
        }

        /// <summary>
        /// Finder class that matches a string if it ends with the given query
        /// </summary>
        private class EndsWithFinder : ArrayFinder {
            /// <summary>
            /// Determines if a specified line matches the given query
            /// </summary>
            /// <param name="value">The value.</param>
            /// <param name="query">The query.</param>
            /// <returns></returns>
            public override bool Match(string value, string query) {
                return value.Trim().EndsWith(query, StringComparison.InvariantCultureIgnoreCase);
            }
        }

        private static readonly EndsWithFinder endsWithFinder = new EndsWithFinder();

        /// <summary>
        /// Returns the first line on an <see cref="ArrayList"/> ending with the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string EndsWith(this ArrayList array, string value) 
        {
            return endsWithFinder.FindValue(array, value);
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
            return endsWithFinder.FindValue(array, value, startIndex);
        }

        /// <summary>
        /// Returns the index of the first line on an <see cref="ArrayList"/> ending with the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static int IndexOfLineEndingWith(this ArrayList array, string value)
        {
            return endsWithFinder.FindIndexOfValue(array, value);
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
            return endsWithFinder.FindIndexOfValue(array, value, startIndex);
        }

        /// <summary>
        /// Finds values in array lists that start with the specified value.
        /// </summary>
        class StartsWithFinder : ArrayFinder {
            /// <summary>
            /// Determines if a specified line matches the given query
            /// </summary>
            /// <param name="value">The value.</param>
            /// <param name="query">The query.</param>
            /// <returns></returns>
            public override bool Match(string value, string query) {
                return value.Trim().StartsWith(query, StringComparison.CurrentCultureIgnoreCase);
            }
        }

        private static readonly ArrayFinder startsWithFinder = new StartsWithFinder();

        /// <summary>
        /// Returns the first line on an <see cref="ArrayList"/> starting with the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string StartsWith(this ArrayList array, string value) 
        {
            return startsWithFinder.FindValue(array, value);
        }

        /// <summary>
        /// Returns the line on an <see cref="ArrayList"/> starting with the specified <see cref="value"/>
        /// starting at <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public static string StartsWith(this ArrayList array, string value, int startIndex) 
        {
            return startsWithFinder.FindValue(array, value, startIndex);
        }

        /// <summary>
        /// Returns the index of the first line on an <see cref="ArrayList"/> starting with the specified <see cref="value"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static int IndexOfLineStartingWith(this ArrayList array, string value) 
        {
            return startsWithFinder.FindIndexOfValue(array, value);
        }

        /// <summary>
        /// Returns the index of the line on an <see cref="ArrayList"/> starting with the specified <see cref="value"/>.
        /// starting at <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public static int IndexOfLineStartingWith(this ArrayList array, string value, int startIndex) 
        {
            return startsWithFinder.FindIndexOfValue(array, value, startIndex);
        }
    }
}
