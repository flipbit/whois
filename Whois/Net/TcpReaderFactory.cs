using System;
using System.Text;
using Whois.Cache;
using Whois.Interfaces;

namespace Whois.Net
{
    /// <summary>
    /// Factory class to create <see cref="TcpReader"/> objects.
    /// </summary>
    public class TcpReaderFactory : ITcpReaderFactory 
    {
        /// <summary>
        /// Creates a <see cref="TcpReader"/> object.
        /// </summary>
        /// <returns></returns>
        public ITcpReader Create()
        {
            // Uses UTF8 by default
            return Create(Encoding.UTF8);
        }

        /// <summary>
        /// Creates an <see cref="ITcpReader"/> object.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        /// <returns></returns>
        public ITcpReader Create(Encoding encoding)
        {
            ITcpReader reader;

            var cachePath = Environment.GetEnvironmentVariable("WHOIS_CACHE_PATH");

            if (string.IsNullOrEmpty(cachePath))
            {
                reader = new TcpReader(encoding);
            }
            else
            {
                reader = new TcpReaderFileCache();
            }

            return reader;
        }
    }
}
