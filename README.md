.NET WHOIS Lookup and Parser
============================
[![GitHub Stars](https://img.shields.io/github/stars/flipbit/whois.svg)](https://github.com/flipbit/whois/stargazers) [![GitHub Issues](https://img.shields.io/github/issues/flipbit/whois.svg)](https://github.com/flipbit/whois/issues) [![NuGet Version](https://img.shields.io/nuget/v/whois.svg)](https://www.nuget.org/packages/Whois/) [![NuGet Downloads](https://img.shields.io/nuget/dt/whois.svg)](https://www.nuget.org/packages/Whois/) 

Query and parse WHOIS domain registration information with this library for .NET Standard 2.0 and .NET Framework 4.5.2.

```csharp
// Create a WhoisLookup instance
var whois = new WhoisLookup();

// Query github.com
var response = whois.Lookup("github.com");

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
var response = whois.Lookup("github.com");

// Convert the response to JSON
var json = JsonConvert.SerializeObject(response, Formatting.Indented);

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

### Async/Await

The library is fully `async/await` compatible.

```csharp
// Create a WhoisLookup instance
var whois = new WhoisLookup();

// Query github.com
var response = await whois.LookupAsync("github.com");

// Output the json 
Console.WriteLine(response.Content);
```

### Configuration

The library can be configured globally or per instance:

```csharp
// Global configuration
WhoisOptions.Defaults.Encoding = Encoding.UTF8;

// Per-instance configuration
var lookup = new WhoisLookup();
lookup.Options.TimeoutSeconds = 30;
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

See the [existing patterns](https://github.com/flipbit/whois/blob/master/Whois/Resources/generic/tld/Found02.txt) and [Tokenizer](https://github.com/flipbit/tokenizer) documentation for information about creating patterns.  You can also add validation and transformation functions to your patterns.

### Networking

The library communicates via an `ITcpReader` interface.  The [default implementation](https://github.com/flipbit/whois/blob/master/Whois/Net/TcpReader.cs) will talk directly to a WHOIS server over port 43.  You can change this behaviour by creating a new `ITcpReader` implementation and registering it the `TcpReaderFactory`:

```csharp        
// Create a custom ITcpReader implementation
class MyCustomTcpReader : ITcpReader
{
  private readonly ITcpReader reader;

  public MyCustomTcpReader()
  {
     reader = new TcpReader();
  }

  public Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds)
  {
    Console.WriteLine($"Reading from URL: {url}");

    return reader.Read(url, port, command, encoding, timeoutSeconds);
  }

  public void Dispose()
  {
    reader.Dispose();
  }
}

// Create a WhoisLookup instance
var lookup = new WhoisLookup();

// Assign the custom TcpReader
lookup.TcpReader = new MyCustomTcpReader();

// Lookups will now use the custom TcpReader
var response = lookup.Lookup("github.com");
```

### Installation

You can install the library via the NuGet GUI or by entering the following command into the Package Manager Console:

    Install-Package Whois
    
The source code is available on Github and can be downloaded and compiled.

### Further Reading

Further details about how the library works can be found on [this blog post](http://flipbit.co.uk/2009/06/querying-whois-server-data-with-c.html).
