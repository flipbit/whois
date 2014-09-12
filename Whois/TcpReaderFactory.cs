using System.Text;
using Whois.Interfaces;

namespace Whois
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
            return new TcpReader(encoding);
        }
    }
}
