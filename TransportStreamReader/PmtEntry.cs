// PmtEntry.cs
public struct PmtEntry
{
    public ushort ProgramNumber { get; set; }
    public ushort PmtPid { get; set; }

    // These fields are new to hold the stream information
    public byte StreamType { get; set; }
    public ushort ElementaryPid { get; set; }
}