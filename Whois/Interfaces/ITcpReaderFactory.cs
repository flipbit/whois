using System.Text;

namespace Whois.Interfaces
{
    /// <summary>
    /// Defines an interface to a faactory class that creates <see cref="ITcpReader"/> objects.
    /// </summary>
    public interface ITcpReaderFactory
    {
        /// <summary>
        /// Creates an <see cref="ITcpReader"/> object.
        /// </summary>
        /// <returns></returns>
        ITcpReader Create();

        /// <summary>
        /// Creates an <see cref="ITcpReader"/> object.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        /// <returns></returns>
        ITcpReader Create(Encoding encoding);
    }
}
