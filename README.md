<p align="center">
  <img src="docs/icon.svg" alt="Whois" width="128" height="128" />
</p>

# Whois
[![GitHub Stars](https://img.shields.io/github/stars/flipbit/whois.svg)](https://github.com/flipbit/whois/stargazers) [![GitHub Issues](https://img.shields.io/github/issues/flipbit/whois.svg)](https://github.com/flipbit/whois/issues) [![NuGet Version](https://img.shields.io/nuget/v/whois.svg)](https://www.nuget.org/packages/Whois/) [![NuGet Downloads](https://img.shields.io/nuget/dt/whois.svg)](https://www.nuget.org/packages/Whois/) 

Query and parse WHOIS domain registration information with this library for .NET Standard 2.0, .NET 8, and .NET 10.

```csharp
// Create a WhoisLookup instance
var lookup = new WhoisLookup();

// Query github.com
var response = await lookup.Lookup("github.com");

// Output the response
Console.WriteLine(response.Content);

// Domain Name: github.com
// Registry Domain ID: 1264983250_DOMAIN_COM-VRSN
// Registrar WHOIS Server: whois.markmonitor.com
// Registrar URL: http://www.markmonitor.com
// ...
```

### Parsing

WHOIS data is parsed into objects using extensible [Tokenizer](https://github.com/flipbit/tokenizer) templates.

```csharp
// Query github.com
var response = await lookup.Lookup("github.com");

// Convert the response to JSON
var json = JsonSerializer.Serialize(response, new JsonSerializerOptions { WriteIndented = true });

// Output the json 
Console.WriteLine(json);

// {
//   "ContentLength": 3730,
//   "Status": 1,
//   "DomainName": {
//     "IsPunyCode": false,
//     "IsTld": false,
//     "Tld": "com",
//     "Value": "github.com"
//   },
//   "RegistryDomainId": "1264983250_DOMAIN_COM-VRSN",
//   "DomainStatus": [
//     "clientUpdateProhibited",
//     "clientTransferProhibited",
//     "clientDeleteProhibited"
//   ],
//   "Registered": "2007-10-09T18:20:50Z",
//   "Updated": "2020-09-08T09:18:27Z",
//   "Expiration": "2022-10-09T07:00:00Z",
// ...
```

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
    FollowReferrer = true
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
    public async Task<WhoisResponse> CheckDomain(string domain, CancellationToken ct)
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

See the [existing patterns](https://github.com/flipbit/whois/blob/master/src/Whois/Resources/generic/tld/Found02.txt) and [Tokenizer](https://github.com/flipbit/tokenizer) documentation for information about creating patterns.  You can also add validation and transformation functions to your patterns.

### Networking

The library communicates via an `ITcpReader` interface.  The [default implementation](https://github.com/flipbit/whois/blob/master/src/Whois/Net/TcpReader.cs) will talk directly to a WHOIS server over port 43.  You can change this behaviour by creating a new `ITcpReader` implementation and passing it to the constructor:

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

### Further Reading

Further details about how the library works can be found on [this blog post](http://flipbit.co.uk/2009/06/querying-whois-server-data-with-c.html).
