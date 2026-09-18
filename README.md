<p align="center">
  <img src="docs/icon.svg" alt="Whois" width="128" height="128" />
</p>

# Whois
[![GitHub Stars](https://img.shields.io/github/stars/flipbit/whois.svg)](https://github.com/flipbit/whois/stargazers) [![GitHub Issues](https://img.shields.io/github/issues/flipbit/whois.svg)](https://github.com/flipbit/whois/issues) [![NuGet Version](https://img.shields.io/nuget/v/whois.svg)](https://www.nuget.org/packages/Whois/) [![NuGet Downloads](https://img.shields.io/nuget/dt/whois.svg)](https://www.nuget.org/packages/Whois/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/flipbit/whois/blob/main/LICENSE.txt)

Query and parse WHOIS and RDAP domain registration data with this library for .NET Standard 2.0, .NET 8, and .NET 10.

```csharp
var lookup = new WhoisLookup();

var result = await lookup.Lookup("github.com");

Console.WriteLine(result.Response.DomainName);     // github.com
Console.WriteLine(result.Response.Registrar?.Name); // MarkMonitor Inc.
Console.WriteLine(result.Response.Expiration);      // 2024-10-09T07:00:00Z
Console.WriteLine(result.Protocol);                 // Rdap (or Whois)
```

### RDAP Support

The library supports [RDAP](https://about.rdap.org/) (Registration Data Access Protocol), the modern replacement for WHOIS. RDAP uses HTTPS and returns structured JSON rather than free-form text.

By default, the library picks the best available protocol automatically - RDAP where it's supported, falling back to WHOIS. You can force a specific protocol with a `WhoisRequest`:

```csharp
// Force RDAP
var result = await lookup.Lookup(new WhoisRequest("github.com")
{
    PreferredProtocol = ProtocolPreference.Rdap
});

// Force legacy WHOIS
var result = await lookup.Lookup(new WhoisRequest("github.com")
{
    PreferredProtocol = ProtocolPreference.Whois
});
```

Both protocols return the same `LookupResult<DomainInfo>` type, so your code doesn't need to care which one was used. `result.Protocol` tells you which was selected, and `result.RawContent` gives you the raw response (WHOIS text or RDAP JSON).

### Structured Data

Both WHOIS and RDAP responses are parsed into the same `DomainInfo` object:

```csharp
var result = await lookup.Lookup("github.com");

var json = JsonSerializer.Serialize(result.Response, new JsonSerializerOptions { WriteIndented = true });
Console.WriteLine(json);

// {
//   "DomainName": "github.com",
//   "RegistryDomainId": "1264983250_DOMAIN_COM-VRSN",
//   "Status": "Registered",
//   "DomainStatus": [
//     "clientDeleteProhibited",
//     "clientTransferProhibited",
//     "clientUpdateProhibited"
//   ],
//   "Registered": "2007-10-09T18:20:50Z",
//   "Updated": "2024-09-08T09:18:27Z",
//   "Expiration": "2026-10-09T07:00:00Z",
//   ...
// }
```

WHOIS text responses are parsed using extensible [Tokenizer](https://github.com/flipbit/tokenizer) templates. RDAP responses are parsed directly from the JSON.

### CancellationToken Support

All async methods accept a `CancellationToken` for cooperative cancellation:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

var response = await lookup.Lookup("github.com", cts.Token);
```

### Configuration

Configure the lookup per-instance using the options constructor parameter:

```csharp
var lookup = new WhoisLookup(new WhoisOptions
{
    TimeoutSeconds = 30,
    FollowReferrer = true,
    PreferredProtocol = ProtocolPreference.Auto // default: RDAP where available, WHOIS fallback
});
```

### Dependency Injection

The library integrates with `Microsoft.Extensions.DependencyInjection` via the `AddWhois()` extension method:

```csharp
// In Startup/Program.cs — configure with a lambda
services.AddWhois(options =>
{
    options.TimeoutSeconds = 30;
    options.FollowReferrer = true;
});

// Or bind from IConfiguration
services.AddWhois(configuration.GetSection("Whois"));
```

Inject `IWhoisLookup` into your services:

```csharp
public class MyService(IWhoisLookup whoisLookup)
{
    public async Task<LookupResult<DomainInfo>> CheckDomain(string domain, CancellationToken ct)
        => await whoisLookup.Lookup(domain, ct);
}
```

### Logging

The library uses `Microsoft.Extensions.Logging`. When registered via DI, an `ILogger<WhoisLookup>` is automatically injected. For standalone use, pass a logger factory explicitly:

```csharp
using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());

var lookup = new WhoisLookup(logger: loggerFactory.CreateLogger<WhoisLookup>());
```

## Extending

### Parsing More Data

If a registrar's WHOIS data isn't being parsed correctly, you can simply add a new template:

```csharp
var lookup = new WhoisLookup();

// Clear the embedded templates (not recommended)
lookup.Parser.ClearTemplates();

// Add a custom WHOIS response parsing template
lookup.Parser.AddTemplate("Domain: { DomainName$ }", "Simple Pattern");
```

See the [existing patterns](https://github.com/flipbit/whois/blob/main/src/Whois/Resources/generic/tld/found/02.txt) and [Tokenizer](https://github.com/flipbit/tokenizer) documentation for information about creating patterns.  You can also add validation and transformation functions to your patterns.

### Networking

The library communicates via an `ITcpReader` interface.  The [default implementation](https://github.com/flipbit/whois/blob/main/src/Whois/Net/TcpReader.cs) will talk directly to a WHOIS server over port 43.  You can change this behaviour by creating a new `ITcpReader` implementation and passing it to the constructor:

```csharp        
// Create a custom ITcpReader implementation
class MyCustomTcpReader : ITcpReader
{
    private readonly ITcpReader _inner = new TcpReader();

    public Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds, CancellationToken cancellationToken)
    {
        Console.WriteLine($"Reading from URL: {url}");

        return _inner.Read(url, port, command, encoding, timeoutSeconds, cancellationToken);
    }
}

// Create a WhoisLookup instance with the custom reader
var lookup = new WhoisLookup(tcpReader: new MyCustomTcpReader());

// Lookups will now use the custom TcpReader
var response = await lookup.Lookup("github.com");
```

### Installation

You can install the library via the NuGet GUI or by entering the following command into the Package Manager Console:

    Install-Package Whois -Version 4.0.0
    
The source code is available on Github and can be downloaded and compiled.

## Contributing

See [CONTRIBUTING.md](https://github.com/flipbit/whois/blob/main/CONTRIBUTING.md) for guidelines on building, testing, and submitting changes.

## Security

To report a security vulnerability, please use [GitHub Security Advisories](https://github.com/flipbit/whois/security/advisories/new). See [SECURITY.md](https://github.com/flipbit/whois/blob/main/SECURITY.md) for guidance on timeouts and rate limiting.

## License

MIT. See [LICENSE.txt](https://github.com/flipbit/whois/blob/main/LICENSE.txt).
