// Pat.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

public class Pat
{
    public ushort TableId { get; }
    public bool SectionSyntaxIndicator { get; }
    public ushort SectionLength { get; }
    public ushort TransportStreamId { get; }
    public byte VersionNumber { get; }
    public bool CurrentNextIndicator { get; }
    public byte SectionNumber { get; }
    public byte LastSectionNumber { get; }
    public List<PatEntry> PatEntries { get; }
    public uint Crc32 { get; }

    public Pat(byte[] payload)
    {
        // Skip pointer field if present
        int offset = 0;
        if (payload[0] == 0x00)
        {
            offset = payload[1] + 1;
        }

        // Parse header
        TableId = payload[offset];
        SectionSyntaxIndicator = ((payload[offset + 1] >> 7) & 0x01) == 1;
        SectionLength = (ushort)(((payload[offset + 1] & 0x0F) << 8) | payload[offset + 2]);
        TransportStreamId = (ushort)((payload[offset + 3] << 8) | payload[offset + 4]);
        VersionNumber = (byte)((payload[offset + 5] & 0x3E) >> 1);
        CurrentNextIndicator = (payload[offset + 5] & 0x01) != 0;
        SectionNumber = payload[offset + 6];
        LastSectionNumber = payload[offset + 7];

        // Parse PAT entries
        PatEntries = new List<PatEntry>();
        int entriesStart = offset + 8;
        int entriesEnd = offset + SectionLength - 4; // Exclude CRC32
        for (int i = entriesStart; i < entriesEnd; i += 4)
        {
            var programNumber = (ushort)((payload[i] << 8) | payload[i + 1]);
            var pmtPid = (ushort)(((payload[i + 2] & 0x1F) << 8) | payload[i + 3]);
            PatEntries.Add(new PatEntry { ProgramNumber = programNumber, PmtPid = pmtPid });
        }

        // Parse CRC32
        Crc32 = (uint)((payload[entriesEnd] << 24) | (payload[entriesEnd + 1] << 16) | (payload[entriesEnd + 2] << 8) | payload[entriesEnd + 3]);
    }
}