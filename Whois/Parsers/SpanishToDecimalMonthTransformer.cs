using System.Text.RegularExpressions;
using Tokens.Transformers;

namespace Whois.Parsers;

/// <summary>
/// Transforms Spanish month names to their decimal equivalents.
/// </summary>
public class SpanishToDecimalMonthTransformer : ITokenTransformer
{
    public bool CanTransform(object value, string[] args, out object transformed)
    {
        if (value is null)
        {
            transformed = null;
            return false;
        }

        var result = value.ToString();

        result = Replace(result, "ene.", "01");
        result = Replace(result, "ene", "01");

        result = Replace(result, "feb.", "02");
        result = Replace(result, "feb", "02");

        result = Replace(result, "mar.", "03");
        result = Replace(result, "mar", "03");

        result = Replace(result, "abr.", "04");
        result = Replace(result, "abr", "04");

        result = Replace(result, "may.", "05");
        result = Replace(result, "may", "05");

        result = Replace(result, "jun.", "06");
        result = Replace(result, "jun", "06");

        result = Replace(result, "jul.", "07");
        result = Replace(result, "jul", "07");

        result = Replace(result, "ago.", "08");
        result = Replace(result, "ago", "08");

        result = Replace(result, "sept.", "09");
        result = Replace(result, "sept", "09");

        result = Replace(result, "oct.", "10");
        result = Replace(result, "oct", "10");

        result = Replace(result, "nov.", "11");
        result = Replace(result, "nov", "11");

        result = Replace(result, "dic.", "12");
        result = Replace(result, "dic", "12");

        transformed = result;

        return transformed != value;
    }

    private static string Replace(string input, string search, string replacement)
    {
        var result = Regex.Replace(
            input,
            Regex.Escape(search), 
            replacement.Replace("$","$$"), 
            RegexOptions.IgnoreCase
        );
        return result;
    }
}