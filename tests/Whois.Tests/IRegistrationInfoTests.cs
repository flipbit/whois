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
}
