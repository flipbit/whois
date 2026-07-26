using Tokens.Transformers;

namespace Whois.Parsers;

/// <summary>
/// Cleans up domain status information
/// </summary>
public class CleanDomainStatusTransformer : ITokenTransformer
{
    public bool TryTransform(object value, string[] args, out object transformed)
    {
        if (value == null)
        {
            transformed = string.Empty;
            return true;
        }

        var valueString = value.ToString() ?? string.Empty;

        var index = valueString.IndexOf("(http", StringComparison.InvariantCultureIgnoreCase);
        if (index > -1)
        {
            transformed = valueString.Substring(0, index).Trim();
            return true;
        }

        index = valueString.IndexOf("http", StringComparison.InvariantCultureIgnoreCase);
        if (index > -1)
        {
            transformed = valueString.Substring(0, index).Trim();
            return true;
        }

        transformed = valueString.Trim();

        return true;
    }
}
