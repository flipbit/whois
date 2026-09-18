# Security Policy

## Reporting a Vulnerability

To report a security vulnerability, please use
[GitHub Security Advisories](https://github.com/flipbit/whois/security/advisories/new).
Don't open a public issue for security vulnerabilities.

## Network Security

WHOIS queries are sent over TCP port 43 as unencrypted plaintext. Both the query and the response travel without encryption, so they can be observed by anyone on the network path. RDAP queries use HTTPS.

WHOIS server responses should not be treated as trusted input. If you're displaying response data in a web page or other user-facing context, sanitise the content appropriately to avoid injection attacks.

## Timeouts and Cancellation

WHOIS servers can be slow or unresponsive. Always use a `CancellationToken` with a bounded timeout to prevent your application from hanging:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
var response = await lookup.Lookup("example.com", cts.Token);
```

The library's `WhoisOptions.TimeoutSeconds` setting provides a default timeout, but a `CancellationToken` gives you more control (particularly if you want to cancel based on user action rather than a fixed deadline).

## Rate Limiting

The library doesn't throttle queries. Many WHOIS servers enforce per-IP query limits and will block clients that send too many requests in a short period. If you're making bulk queries, implement your own rate limiting to stay within server limits.
