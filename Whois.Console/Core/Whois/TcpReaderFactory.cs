using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois
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
            return new TcpReader();
        }
    }
}
