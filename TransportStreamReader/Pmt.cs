// Pmt.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

public class Pmt
{
    public ushort TableId { get; }
    public bool SectionSyntaxIndicator { get; }
    public ushort SectionLength { get; }
    public ushort ProgramNumber { get; }
    public byte VersionNumber { get; }
    public bool CurrentNextIndicator { get; }
    public byte SectionNumber { get; }
    public byte LastSectionNumber { get; }
    public ushort PcrPid { get; }
    public ushort ProgramInfoLength { get; }
    public List<PmtComponentEntry> Components { get; }
    public uint Crc32 { get; }

    public Pmt(byte[] payload)
    {
        // Skip pointer field if present
        int offset = 0;
        if (payload.Length > 0 && payload[0] == 0x00)
        {
            if (payload.Length > 1)
            {
                offset = payload[1] + 1;
            }
        }

        // Check if payload is big enough for the fixed part of the header
        if (payload.Length < offset + 12)
        {
            // The payload is too short, we cannot parse it.
            // Initialize properties to default values.
            TableId = 0;
            SectionSyntaxIndicator = false;
            SectionLength = 0;
            ProgramNumber = 0;
            VersionNumber = 0;
            CurrentNextIndicator = false;
            SectionNumber = 0;
            LastSectionNumber = 0;
            PcrPid = 0;
            ProgramInfoLength = 0;
            Components = new List<PmtComponentEntry>();
            Crc32 = 0;
            return;
        }

        // Parse header
        TableId = payload[offset];
        SectionSyntaxIndicator = ((payload[offset + 1] >> 7) & 0x01) == 1;
        SectionLength = (ushort)(((payload[offset + 1] & 0x0F) << 8) | payload[offset + 2]);
        ProgramNumber = (ushort)((payload[offset + 3] << 8) | payload[offset + 4]);
        VersionNumber = (byte)((payload[offset + 5] & 0x3E) >> 1);
        CurrentNextIndicator = (payload[offset + 5] & 0x01) != 0;
        SectionNumber = payload[offset + 6];
        LastSectionNumber = payload[offset + 7];
        PcrPid = (ushort)(((payload[offset + 8] & 0x1F) << 8) | payload[offset + 9]);
        ProgramInfoLength = (ushort)(((payload[offset + 10] & 0x0F) << 8) | payload[offset + 11]);

        // Check if the payload contains the full section
        if (payload.Length < offset + SectionLength + 3) // +3 for the rest of the fixed header + CRC32
        {
            // The payload is too short for the stated SectionLength
            Components = new List<PmtComponentEntry>();
            Crc32 = 0;
            return;
        }

        // Parse PMT components
        Components = new List<PmtComponentEntry>();
        int componentsStart = offset + 12 + ProgramInfoLength;
        int componentsEnd = offset + SectionLength - 4; // Exclude CRC32
        int currentIndex = componentsStart;

        while (currentIndex + 5 <= componentsEnd) // Ensure at least 5 bytes for stream info
        {
            var streamType = payload[currentIndex];
            var elementaryPid = (ushort)(((payload[currentIndex + 1] & 0x1F) << 8) | payload[currentIndex + 2]);
            var esInfoLength = (ushort)(((payload[currentIndex + 3] & 0x0F) << 8) | payload[currentIndex + 4]);

            if (currentIndex + 5 + esInfoLength > componentsEnd)
            {
                // This component's descriptor loop is truncated. Break the loop.
                break;
            }

            Components.Add(new PmtComponentEntry
            {
                ElementaryPid = elementaryPid,
                StreamType = streamType
            });

            // Move to the next component
            currentIndex += 5 + esInfoLength;
        }

        // Parse CRC32
        if (offset + SectionLength + 3 < payload.Length)
        {
            int crcStart = offset + SectionLength - 1;
            Crc32 = (uint)((payload[crcStart] << 24) | (payload[crcStart + 1] << 16) | (payload[crcStart + 2] << 8) | payload[crcStart + 3]);
        }
        else
        {
            Crc32 = 0; // CRC32 is not present
        }
    }
}