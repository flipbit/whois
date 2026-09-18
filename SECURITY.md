# Security Policy

## Reporting a Vulnerability

To report a security vulnerability, please use
[GitHub Security Advisories](https://github.com/flipbit/whois/security/advisories/new).
Don't open a public issue for security vulnerabilities.

## Network Security

WHOIS queries are sent over TCP port 43 as unencrypted plaintext. Both the query and the response travel without encryption, so they can be observed by anyone on the network path. RDAP queries use HTTPS.

WHOIS and RDAP responses contain registrant-supplied data - anyone can register a domain and set the registrant name, organisation, address, and contact details to arbitrary strings. These values appear verbatim in the response and should be treated as untrusted input.

If you're displaying fields like `response.Registrant.Name` in a web page, sanitise them to prevent XSS. If you're interpolating them into database queries, use parameterised queries. The same applies to RDAP responses.

## Timeouts and Cancellation

WHOIS servers can be slow or unresponsive. Always use a `CancellationToken` with a bounded timeout to prevent your application from hanging:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
var response = await lookup.Lookup("example.com", cts.Token);
```

The library's `WhoisOptions.TimeoutSeconds` setting provides a default timeout, but a `CancellationToken` gives you more control (particularly if you want to cancel based on user action rather than a fixed deadline).

## Rate Limiting

The library doesn't throttle queries. Many WHOIS servers enforce per-IP query limits and will block clients that send too many requests in a short period. If you're making bulk queries, implement your own rate limiting to stay within server limits.
