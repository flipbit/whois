namespace WhoisMigration;

public static class SampleMapper
{
    // Ordered longest-first so "not_found" matches before "not" (if it existed)
    private static readonly (string Prefix, string Status)[] StatusPrefixes =
    [
        ("not_found", "not-found"),
        ("not_assigned", "not-assigned"),
        ("not_available", "not-available"),
        ("out_of_service", "out-of-service"),
        ("to_be_released", "to-be-released"),
        ("pending_delete", "pending-delete"),
        ("found", "found"),
        ("error", "error"),
        ("throttled", "throttled"),
        ("reserved", "reserved"),
        ("invalid", "invalid"),
        ("blocked", "blocked"),
        ("suspended", "suspended"),
        ("inactive", "inactive"),
        ("quarantined", "quarantined"),
        ("unavailable", "unavailable"),
        ("prohibited", "prohibited"),
        ("expired", "expired"),
        ("deactivated", "deactivated"),
        ("failed", "failed"),
        ("locked", "locked"),
        ("redemption", "redemption"),
        ("unconfirmed", "unconfirmed"),
        ("other_status", "found"),
    ];

    public static (string Status, string Filename) MapToStatusDirectory(string sampleFilename)
    {
        var nameWithoutExt = Path.GetFileNameWithoutExtension(sampleFilename);

        foreach (var (prefix, status) in StatusPrefixes)
        {
            if (nameWithoutExt.Equals(prefix, StringComparison.OrdinalIgnoreCase) ||
                nameWithoutExt.StartsWith(prefix + "_", StringComparison.OrdinalIgnoreCase))
            {
                return (status, sampleFilename);
            }
        }

        // Domain-named samples (e.g. adobe.com.txt, youtu.be.txt) are found-status
        // samples capturing a specific real domain response.
        return ("found", sampleFilename);
    }
}
