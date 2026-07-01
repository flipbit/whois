using Tokens;

namespace Whois.Parsers.Fixups
{
    /// <summary>
    /// Helper class to fix up data on a WHOIS result
    /// </summary>
    public interface IFixup
    {
        /// <summary>
        /// Determines if this Fixup can be applied to the given response.
        /// </summary>
        bool CanFixup(TokenizeResult<WhoisResponse> result);

        /// <summary>
        /// Fixes the given result.
        /// </summary>
        void Fixup(TokenizeResult<WhoisResponse> result);

    }
}
