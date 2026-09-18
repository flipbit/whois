# Architecture

## Lookup Pipeline

`WhoisLookup` orchestrates the full query flow:

1. **Server Discovery** (`Servers/IanaServerLookup`) - queries `whois.iana.org` to find the authoritative WHOIS server for a TLD
2. **Download** (`Net/TcpReader` via `ITcpReader`) - connects to the WHOIS server over TCP port 43. `TcpReader` is stateless (creates a new `TcpClient` per call) and supports `CancellationToken` for timeouts via `CancellationTokenSource.CancelAfter`.
3. **Parse** (`Parsers/WhoisParser`) - matches the raw text response against Tokenizer templates to produce a structured `WhoisResponse`
4. **Referrer Chain** - follows WHOIS referral servers (e.g. Verisign -> registrar) until no further referrer is found or a loop is detected

## RDAP Pipeline

For domains that support RDAP, `RdapLookup` provides a parallel lookup path:

1. **Bootstrap** (`Rdap/Bootstrap/RdapBootstrapClient`) - queries the IANA RDAP bootstrap registry to find the authoritative RDAP server for a TLD
2. **Query** (`Rdap/RdapClient`) - sends an HTTPS request to the RDAP server and deserialises the JSON response
3. **Map** - converts the RDAP response into the same `WhoisResponse` structure used by the WHOIS pipeline

## API Design

- **Async-only** - all public methods return `Task<T>` and accept `CancellationToken cancellationToken = default`. No sync wrappers.
- **No `IDisposable`** - `IWhoisLookup`, `ITcpReader`, and `IWhoisServerLookup` aren't disposable (`TcpReader` is stateless).
- **DI support** - `services.AddWhois()` registers all services. Accepts `Action<WhoisOptions>` or `IConfiguration` for configuration.
- **Logging** - uses `Microsoft.Extensions.Logging.Abstractions` (`ILogger<T>`). Defaults to `NullLogger` when constructed without DI.
- **Options pattern** - `WhoisOptions` works with `IOptions<WhoisOptions>` for DI or can be passed directly.

## netstandard2.0 Compatibility

`#if` conditional compilation is centralised in `src/Whois/Net/NetStandardShims.cs`. This is the only file with `#if` directives. It provides shims for `ConnectAsync(CancellationToken)` and `ReadLineAsync(CancellationToken)` which don't exist on netstandard2.0.

## Template-Based Parsing

Parsing uses the external [Tokenizer](https://github.com/flipbit/tokenizer) library (`TokenMatcher`). Templates are embedded resources in `src/Whois/Resources/` (included via glob: `Resources/**/*.txt`), organised by WHOIS server hostname (e.g. `Resources/whois.nic.uk/uk/Found.txt`). The parser:

- First tries server-specific templates (tagged with the server hostname)
- Falls back to generic catch-all templates in `Resources/generic/tld/`
- Applies `IFixup` post-processing steps (e.g. `MultipleContactFixup`) after template matching

## Test Structure

- **Whois.Tests** - unit tests using xUnit + NSubstitute. Parsing tests live in `tests/Whois.Tests/Parsing/` mirroring the server directory structure. Each test class extends `ParsingTests` and uses `SampleReader` to load sample WHOIS responses from `tests/Whois.Tests/Samples/` (also organised by server/TLD). Sample files in tests mirror the embedded resource structure in the main library.
- **Whois.Tests.Integration** - live network tests against real WHOIS servers (including ReadmeTests that demonstrate API usage)
