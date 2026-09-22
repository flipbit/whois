using Tokens;
using Tokens.Exceptions;
using Whois.Parsers.Fixups;
using Whois.Protocols;

namespace Whois.Parsers;

/// <summary>
/// Parser to turn WHOIS server responses into <see cref="WhoisRecord"/>
/// objects.
/// </summary>
public class WhoisParser
{
    private const string GenericTemplateTag = "catch-all";
    private static readonly string[] CatchAllTags = [GenericTemplateTag];

    private readonly TemplateMatcher _matcher;
#pragma warning disable MA0158 // System.Threading.Lock is not available on netstandard2.0 / net8.0
    private readonly object _loadLock = new();
#pragma warning restore MA0158

    /// <summary>
    /// Creates a new instance of the <see cref="WhoisParser"/> class.
    /// </summary>
    public WhoisParser()
    {
        var options = new TokenizerOptions()
            .WithTransformer<CleanDomainStatusTransformer>()
            .WithTransformer<ToHostNameTransformer>();

        _matcher = new TemplateMatcher(options);
        FixUps = new List<IFixup>();

        // Register default FixUps
        FixUps.Add(new MultipleContactFixup());
        FixUps.Add(new WhoisIsocOrgIlFixup());
    }

    /// <summary>
    /// Contains the registered templates
    /// </summary>
    public TemplateCollection Templates => _matcher.Templates;

    /// <summary>
    /// Template Fixups
    /// </summary>
    internal IList<IFixup> FixUps { get; }

    /// <summary>
    /// Parses the WHOIS server response for the given server and TLD.
    /// </summary>
    internal WhoisRecord Parse(string whoisServer, string content)
    {
        return Parse<WhoisRecord>(whoisServer, content);
    }

    /// <summary>
    /// Parses the WHOIS server response, assigning fields to type T.
    /// </summary>
    internal T Parse<T>(string whoisServer, string content) where T : class, new()
    {
        if (string.IsNullOrEmpty(content))
        {
            return new T();
        }

        LoadServerTemplates(whoisServer);

        var result = _matcher.Tokenize(content, new[] { whoisServer });

        var match = result.BestMatch;

        if (match == null)
        {
            LoadServerGenericTemplates();

            match = _matcher
                .Tokenize(content, CatchAllTags)
                .BestMatch;
        }

        if (match != null)
        {
            T value;
            var assignmentErrors = 0;
            try
            {
                value = match.Assign<T>();
            }
            catch (AssignmentFailedException ex)
            {
                value = (T)ex.PartialResult!;
                assignmentErrors = ex.Errors.Count;
            }

            SetDiagnostics(value, whoisServer, content, match, assignmentErrors);

            return value;
        }

        return new T();
    }

    private void SetDiagnostics<T>(T value, string whoisServer, string content, TokenizeResult match, int assignmentErrors)
    {
        var fieldsParsed = match.Tokens.Matches.Count;
        var parsingErrors = match.Exceptions.Count + assignmentErrors;
        var templateName = match.Template.Name;

        if (value is WhoisRecord whois)
        {
            // Perform extended processing on parsed data via FixUps.
            foreach (var fixup in FixUps)
            {
                if (fixup.CanFixup(match))
                {
                    fixup.Fixup(match, whois);
                }
            }

            whois.Content = content;
            whois.FieldsParsed = fieldsParsed;
            whois.ParsingErrors = parsingErrors;
            whois.TemplateName = templateName;

            var status = WhoisStatusParser.Parse(
                whoisServer,
                whois.DomainStatus.FirstOrDefault(),
                whois.Status);

            whois.Status = status;
        }
        else if (value is IpRecord ip)
        {
            ip.Content = content;
            ip.FieldsParsed = fieldsParsed;
            ip.ParsingErrors = parsingErrors;
            ip.TemplateName = templateName;
        }
    }

    public void AddTemplate(string content, string name)
    {
        _matcher.RegisterTemplate(content, name);
    }

    public void ClearTemplates()
    {
        _matcher.Templates.Clear();
    }

    /// <summary>
    /// Loads all .txt template files from the given directory and registers them with the matcher.
    /// </summary>
    public void LoadServerTemplatesFromDirectory(string whoisServer, string directoryPath)
    {
        if (Templates.ContainsTag(whoisServer)) return;

        lock (_loadLock)
        {
            if (Templates.ContainsTag(whoisServer)) return;

            foreach (var file in Directory.GetFiles(directoryPath, "*.txt"))
            {
                var content = File.ReadAllText(file);
                _matcher.RegisterTemplate(content);
            }
        }
    }

    private void LoadServerTemplates(string whoisServer)
    {
        // Fast check outside the lock  -  avoid taking the lock when already loaded.
        if (Templates.ContainsTag(whoisServer)) return;

        lock (_loadLock)
        {
            // Double-checked locking: re-verify under the lock before loading.
            if (Templates.ContainsTag(whoisServer)) return;

            var templateNames = ResourceReader.GetNames(whoisServer);

            foreach (var templateName in templateNames)
            {
                var content = ResourceReader.GetContent(templateName);

                _matcher.RegisterTemplate(content);
            }
        }
    }

    private void LoadServerGenericTemplates()
    {
        if (Templates.ContainsTag(GenericTemplateTag)) return;

        lock (_loadLock)
        {
            if (Templates.ContainsTag(GenericTemplateTag)) return;

            var templateNames = ResourceReader.GetNames("generic", "tld");

            foreach (var templateName in templateNames)
            {
                var content = ResourceReader.GetContent(templateName);

                _matcher.RegisterTemplate(content);
            }
        }
    }
}
