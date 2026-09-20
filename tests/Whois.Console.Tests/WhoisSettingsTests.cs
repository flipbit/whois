using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Spectre.Console.Cli;
using Whois.Commands;
using Whois.Infrastructure;
using Xunit;

namespace Whois.Console.Tests;

public class WhoisSettingsTests
{
    private static (CommandApp<WhoisCommand>, IWhoisLookup) BuildApp()
    {
        var lookup = Substitute.For<IWhoisLookup>();
        var emptyResult = new LookupResult<DomainInfo>(new DomainInfo(), LookupProtocol.Whois, string.Empty, new LookupDiagnostics());
        lookup.Lookup(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>())
              .Returns(Task.FromResult(emptyResult));

        var services = new ServiceCollection();
        services.AddSingleton(lookup);

        var registrar = new TypeRegistrar(services);
        var app = new CommandApp<WhoisCommand>(registrar);
        app.Configure(config => config.PropagateExceptions());

        return (app, lookup);
    }

    [Fact]
    public async Task Host_ParsesShortFlag()
    {
        var (app, lookup) = BuildApp();

        await app.RunAsync(["example.com", "-h", "whois.verisign-grs.com"]);

        await lookup.Received(1).Lookup(
            Arg.Is<WhoisRequest>(r => r.WhoisServer != null && r.WhoisServer.Value == "whois.verisign-grs.com"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Host_ParsesLongFlag()
    {
        var (app, lookup) = BuildApp();

        await app.RunAsync(["example.com", "--host", "whois.verisign-grs.com"]);

        await lookup.Received(1).Lookup(
            Arg.Is<WhoisRequest>(r => r.WhoisServer != null && r.WhoisServer.Value == "whois.verisign-grs.com"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Port_ParsesShortFlag()
    {
        var (app, lookup) = BuildApp();

        await app.RunAsync(["example.com", "-p", "4343"]);

        await lookup.Received(1).Lookup(
            Arg.Is<WhoisRequest>(r => r.Port == 4343),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Port_ParsesLongFlag()
    {
        var (app, lookup) = BuildApp();

        await app.RunAsync(["example.com", "--port", "4343"]);

        await lookup.Received(1).Lookup(
            Arg.Is<WhoisRequest>(r => r.Port == 4343),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Timeout_ParsesFlag()
    {
        var (app, lookup) = BuildApp();

        await app.RunAsync(["example.com", "--timeout", "30"]);

        await lookup.Received(1).Lookup(
            Arg.Is<WhoisRequest>(r => r.TimeoutSeconds == 30),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Rdap_ParsesFlag()
    {
        var (app, lookup) = BuildApp();

        await app.RunAsync(["example.com", "--rdap"]);

        await lookup.Received(1).Lookup(
            Arg.Is<WhoisRequest>(r => r.PreferredProtocol == ProtocolPreference.Rdap),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Whois_ParsesFlag()
    {
        var (app, lookup) = BuildApp();

        await app.RunAsync(["example.com", "--whois"]);

        await lookup.Received(1).Lookup(
            Arg.Is<WhoisRequest>(r => r.PreferredProtocol == ProtocolPreference.Whois),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RdapAndWhois_AreMutuallyExclusive()
    {
        var (app, _) = BuildApp();

        var ex = await Assert.ThrowsAsync<CommandRuntimeException>(
            () => app.RunAsync(["example.com", "--rdap", "--whois"]));

        Assert.Contains("Cannot specify both --rdap and --whois", ex.Message, StringComparison.Ordinal);
    }
}
