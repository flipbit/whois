using System.Collections;

namespace Whois.Arrays
{
    /// <summary>
    /// Finds values in <see cref="ArrayList"/>s.
    /// </summary>
    public abstract class ArrayFinder
    {
        /// <summary>
        /// Finds the first instance of the value in the array.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public string FindValue(ArrayList array, string value)
        {
            return FindValue(array, value, 0);
        }

        /// <summary>
        /// Finds the instance of the value in the array starting at <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public string FindValue(ArrayList array, string value, int startIndex)
        {
            var result = string.Empty;

            var index = FindIndexOfValue(array, value, startIndex);

            if (index > -1)
            {
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
        public int FindIndexOfValue(ArrayList array, string value)
        {
            return FindIndexOfValue(array, value, 0);
        }

        /// <summary>
        /// Finds the index of the value in the array starting as <see cref="startIndex"/>.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <param name="value">The value.</param>
        /// <param name="startIndex">The start index.</param>
        /// <returns></returns>
        public int FindIndexOfValue(ArrayList array, string value, int startIndex)
        {
            var result = -1;

            for (var i = startIndex; i <= array.Count - 1; i++)
            {
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
}