using System.Text;
using Flipbit.Core.Whois.Domain;

namespace Flipbit.Core.Whois.Interfaces
{
    /// <summary>
    /// Interface to download WHOIS records
    /// </summary>
    public interface IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        Encoding CurrentEncoding { get; }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        WhoisRecord Visit(WhoisRecord record);
    }
}