namespace Flipbit.Core.Whois.Interfaces
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
    }
}
