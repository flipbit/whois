.NET WHOIS Lookup
=====

.NET WHOIS is a drop-in library that enables you to query WHOIS information for domain registrations in .NET projects.  The library doesn't have any dependencies and returns an object representing the WHOIS data.

### Installation

You can install the library via the NuGet GUI or by entering the following command into the Package Manager Console:

    Install-Package Whois
    
The source code is available on Github and can be downloaded and compiled.

### Usage

To use the library, reference it in your project and then use the following code:

```csharp
using namespace Whois;
var whois = new WhoisLookup().Lookup("github.com");
Console.WriteLine(whois.ToString());
```

### How The Library Works

The library works by querying [CenterGate’s whois-servers.net] [1] in order to find the correct WHOIS server for the TLD.
The TLD WHOIS server is then queried in order to get the WHOIS information for the domain.  Queries to WHOIS servers are 
made using TCP.

<div style="text-align: center;">
    <img src="https://raw.github.com/flipbit/whois/master/Docs/Workflow.png" alt="Whois Query Flow Diagram" />
</div>

### Extending

As WHOIS data is returned in free text format, custom Visitor classes need to be written to extract information
and return it in a structured format.  Currently only the registration date is returned for a number of registrars,
however this can easily be extended by writing new visitors.

### Further Reading

Further details about how the library works can be found on [this blog post] [2].

  [1]: http://www.centergate.com/                                           "CenterGate's WHOIS lookup service"
  [2]: http://flipbit.co.uk/2009/06/querying-whois-server-data-with-c.html  "Querying WHOIS server data with C#"
