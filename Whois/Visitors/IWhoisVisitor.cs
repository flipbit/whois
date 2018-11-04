using System.Threading.Tasks;

namespace Whois.Visitors
{
    /// <summary>
    /// Performs an operation on the current WHOIS lookup state 
    /// </summary>
    public interface IWhoisVisitor
    {
        /// <summary>
        /// Visits the current WHOIS lookup state and performs an operation on it.
        /// </summary>
        Task<LookupState> Visit(LookupState state);
    }
}