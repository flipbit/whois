namespace Whois.Servers;

/// <summary>
/// Fake class used for testing.
/// </summary>
internal class FakeWhoisServerLookup : IWhoisServerLookup
{
    public Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar
            {
                WhoisServer = new HostName("test.whois.com"),
            },
        });
    }
}
