using Flipbit.Core.Whois.Domain;

namespace Flipbit.Core.Whois.Interfaces
{
    /// <summary>
    /// Interface to download WHOIS records
    /// </summary>
    public interface IWhoisVisitor
    {
        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        WhoisRecord Visit(WhoisRecord record);
    }
}