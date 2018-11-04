.NET WHOIS Lookup and Parser
============================
[![GitHub Stars](https://img.shields.io/github/stars/flipbit/whois.svg)](https://github.com/flipbit/whois/stargazers) [![GitHub Issues](https://img.shields.io/github/issues/flipbit/whois.svg)](https://github.com/flipbit/whois/issues) [![NuGet Version](https://img.shields.io/nuget/v/whois.svg)](https://www.nuget.org/packages/Whois/) [![NuGet Downloads](https://img.shields.io/nuget/dt/whois.svg)](https://www.nuget.org/packages/Whois/) 

Query and parse WHOIS domain registration information with this library for .NET Standard 2.0 and .NET Framework 4.5.2.

```csharp
var whois = new WhoisLookup();
var response = whois.Lookup("github.com");

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
var response = whois.Lookup("github.com");
var json = JsonConvert.SerializeObject(response.ParsedResponse, Formatting.Indented);

Console.WriteLine(json);

// {
//   "DomainName": "github.com",
//   "RegistryDomainId": "1264983250_DOMAIN_COM-VRSN",
//   "Expiration": "2020-10-09T20:20:50+02:00",
//   "Registrar": {
//     "Name": "MarkMonitor, Inc.",
//     "Url": "http://www.markmonitor.com",
// ...
```

### Async/Await

The library is fully `async/await` compatible.

```csharp
public async Task<string> GetWhois()
{
    var whois = new WhoisLookup();
    var response = await whois.LookupAsync("github.com");
    return response.Content;
}
```

### Configuration

The library can be configured globally or per instance:

```csharp
// Global configuration
WhoisOptions.Defaults.DefaultEncoding = Encoding.ASCII;

// Instance configuration
var lookup = new WhoisLookup();
lookup.Options.ParseWhoisResponse = false;
```

## Extending

### Parsing More Data

If a registrar's WHOIS data isn't being parsed correctly, you can simply add a new template:

```csharp
var lookup = new WhoisLookup();

// Clear embedded patterns
lookup.ClearPatterns()

// Add new pattern
lookup.AddPattern("Domain: {DomainName$}", "Simple Pattern")
```

See the [existing patterns](https://github.com/flipbit/whois/blob/master/Whois/Resources/Patterns/Domains/RegistrarSafe.txt) and [Tokenizer](https://github.com/flipbit/tokenizer) documentation for information about creating patterns.  You can also add validation and transformation functions to your patterns.

### Networking

The library communicates via an `ITcpReader` interface.  The [default implementation](https://github.com/flipbit/whois/blob/master/Whois/Net/TcpReader.cs) will talk directly to a WHOIS server over port 43.  You can change this behaviour by creating a new `ITcpReader` implementation and registering it the `TcpReaderFactory`:

```csharp
// Custom implementation
class MyCustomTcpReader : ITcpReader
{
    ...
}

// Register
TcpReaderFactory.Bind(() => new MyCustomTcpReader());
```

### Installation

You can install the library via the NuGet GUI or by entering the following command into the Package Manager Console:

    Install-Package Whois
    
The source code is available on Github and can be downloaded and compiled.

### Further Reading

Further details about how the library works can be found on [this blog post](http://flipbit.co.uk/2009/06/querying-whois-server-data-with-c.html).
