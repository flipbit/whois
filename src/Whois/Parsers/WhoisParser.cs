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
    private readonly Func<string, string?>? _cacheResolver;

    /// <summary>
    /// Creates a new instance of the <see cref="WhoisParser"/> class.
    /// </summary>
    public WhoisParser() : this(cacheResolver: null)
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="WhoisParser"/> class with an optional cache resolver.
    /// When <paramref name="cacheResolver"/> is non-null, it is called with the WHOIS server name
    /// to retrieve a directory path containing pre-cached template files. When it returns null,
    /// embedded resources are used instead.
    /// </summary>
    public WhoisParser(Func<string, string?>? cacheResolver)
    {
        var options = new TokenizerOptions()
            .WithTransformer<CleanDomainStatusTransformer>()
            .WithTransformer<ToHostNameTransformer>();

        _matcher = new TemplateMatcher(options);
        _cacheResolver = cacheResolver;
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
        if (string.IsNullOrEmpty(content))
        {
            return new WhoisRecord
            {
                Content = content,
                Status = RegistrationStatus.Unknown,
            };
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
            WhoisRecord value;
            var assignmentErrors = 0;
            try
            {
                value = match.Assign<WhoisRecord>();
            }
            catch (AssignmentFailedException ex)
            {
                value = (WhoisRecord)ex.PartialResult!;
                assignmentErrors = ex.Errors.Count;
            }

            // Perform extended processing on parsed data
            // via FixUps.
            foreach (var fixup in FixUps)
            {
                if (fixup.CanFixup(match))
                {
                    fixup.Fixup(match, value);
                }
            }

            value.Content = content;
            value.FieldsParsed = match.Tokens.Matches.Count;
            value.ParsingErrors = match.Exceptions.Count + assignmentErrors;
            value.TemplateName = match.Template.Name;

            var status = WhoisStatusParser.Parse(whoisServer, value.DomainStatus.FirstOrDefault(), value.Status);

            value.Status = status;

            return value;
        }

        return new WhoisRecord
        {
            Content = content,
            Status = RegistrationStatus.Unknown,
        };
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

            if (_cacheResolver != null)
            {
                var directoryPath = _cacheResolver(whoisServer);
                if (directoryPath != null)
                {
                    foreach (var file in Directory.GetFiles(directoryPath, "*.txt"))
                    {
                        var content = File.ReadAllText(file);
                        _matcher.RegisterTemplate(content);
                    }
                    return;
                }
            }

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
