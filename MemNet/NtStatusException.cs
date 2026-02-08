/// <summary>
/// Exception thrown when an NT API function fails with an NTSTATUS error code.
/// </summary>
public class NtStatusException : Exception
{
    /// <summary>
    /// The NTSTATUS error code.
    /// </summary>
    public int NtStatus { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="NtStatusException"/> class.
    /// </summary>
    /// <param name="ntStatus">The NTSTATUS error code.</param>
    /// <param name="message">The error message.</param>
    public NtStatusException(int ntStatus, string message)
        : base($"{message} (NTSTATUS: 0x{ntStatus:X8})")
    {
        NtStatus = ntStatus;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="NtStatusException"/> class.
    /// </summary>
    /// <param name="ntStatus">The NTSTATUS error code.</param>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public NtStatusException(int ntStatus, string message, Exception innerException)
        : base($"{message} (NTSTATUS: 0x{ntStatus:X8})", innerException)
    {
        NtStatus = ntStatus;
    }
}