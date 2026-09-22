using Xunit;

namespace Whois;

public class IRegistrationInfoTests
{
    [Fact]
#pragma warning disable CA1859
    public void DomainInfo_Implements_IRegistrationInfo()
    {
        IRegistrationInfo info = new DomainInfo
        {
            Status = RegistrationStatus.Found,
            Registered = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Updated = new DateTime(2021, 6, 15, 0, 0, 0, DateTimeKind.Utc),
            Remarks = "Test remarks",
        };

        Assert.Equal(RegistrationStatus.Found, info.Status);
        Assert.Equal(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc), info.Registered);
        Assert.Equal(new DateTime(2021, 6, 15, 0, 0, 0, DateTimeKind.Utc), info.Updated);
        Assert.Equal("Test remarks", info.Remarks);
    }
#pragma warning restore CA1859

    [Fact]
#pragma warning disable CA1859
    public void IpInfo_Implements_IRegistrationInfo()
    {
        IRegistrationInfo info = new IpInfo
        {
            Status = RegistrationStatus.Found,
            Registered = new DateTime(2010, 3, 1, 0, 0, 0, DateTimeKind.Utc),
            Updated = new DateTime(2023, 7, 20, 0, 0, 0, DateTimeKind.Utc),
            Remarks = "IP allocation remarks",
        };

        Assert.Equal(RegistrationStatus.Found, info.Status);
        Assert.Equal(new DateTime(2010, 3, 1, 0, 0, 0, DateTimeKind.Utc), info.Registered);
        Assert.Equal(new DateTime(2023, 7, 20, 0, 0, 0, DateTimeKind.Utc), info.Updated);
        Assert.Equal("IP allocation remarks", info.Remarks);
    }
#pragma warning restore CA1859

    [Fact]
    public void IpInfo_Properties()
    {
        var abuse = new Contact { Name = "Abuse Team", Email = "abuse@example.com" };
        var info = new IpInfo
        {
            Network = "8.8.8.0 - 8.8.8.255",
            Cidr = "8.8.8.0/24",
            NetName = "GOGL",
            Organization = "Google LLC",
            Country = "US",
            Rir = "ARIN",
            Status = RegistrationStatus.Found,
            AbuseContact = abuse,
        };

        Assert.Equal("8.8.8.0 - 8.8.8.255", info.Network);
        Assert.Equal("8.8.8.0/24", info.Cidr);
        Assert.Equal("GOGL", info.NetName);
        Assert.Equal("Google LLC", info.Organization);
        Assert.Equal("US", info.Country);
        Assert.Equal("ARIN", info.Rir);
        Assert.Equal(RegistrationStatus.Found, info.Status);
        Assert.Same(abuse, info.AbuseContact);
    }
}
