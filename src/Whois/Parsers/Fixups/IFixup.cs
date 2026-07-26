using Tokens;
using Whois.Protocols;

namespace Whois.Parsers.Fixups;

internal interface IFixup
{
    public bool CanFixup(TokenizeResult result);
    public void Fixup(TokenizeResult result, WhoisRecord record);
}
