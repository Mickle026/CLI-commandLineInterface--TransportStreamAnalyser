// TransportStreamReader.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Collections.Concurrent; // Added for thread-safe collections

public class TransportStreamReader
{
    private readonly string _filePath;
    private readonly HashSet<PatEntry> _loggedPatEntries = new HashSet<PatEntry>();
    private readonly HashSet<ushort> _loggedPmtPids = new HashSet<ushort>();

    public TransportStreamReader(string filePath)
    {
        _filePath = filePath;
    }

    public List<TransportStreamPacket> ReadPackets()
    {
        if (!File.Exists(_filePath))
        {
            Console.WriteLine($"Error: File not found at '{_filePath}'.");
            return new List<TransportStreamPacket>();
        }

        Console.WriteLine($"\n--- Transport Stream File: '{Path.GetFileName(_filePath)}' ---");

        long fileSize = new FileInfo(_filePath).Length;
        int totalPackets = (int)(fileSize / TransportStreamPacket.PacketSize);

        Console.WriteLine($"Total Packets to Read: {totalPackets}");
        Console.WriteLine($"Packet Size: {TransportStreamPacket.PacketSize} bytes");
        Console.WriteLine("\nStarting analysis...");

        var packets = new List<TransportStreamPacket>();
        int packetsRead = 0;

        try
        {
            using (var fs = new FileStream(_filePath, FileMode.Open, FileAccess.Read))
            using (var reader = new BinaryReader(fs))
            {
                Console.Write("Progress: 0.00% | 0 / 0 packets");

                while (fs.Position < fileSize)
                {
                    byte[] buffer = reader.ReadBytes(TransportStreamPacket.PacketSize);

                    if (buffer.Length < TransportStreamPacket.PacketSize)
                    {
                        Console.WriteLine($"\nWarning: File size is not a multiple of {TransportStreamPacket.PacketSize}. Last {buffer.Length} bytes were not processed.");
                        break;
                    }

                    try
                    {
                        var packet = new TransportStreamPacket(buffer);
                        // Add a check to ensure the packet is valid before adding
                        if (packet.SyncByte != 0x47)
                        {
                            // It's a malformed packet, skip it.
                            continue;
                        }

                        packets.Add(packet);
                        packetsRead++;

                        if (packetsRead % 1000 == 0 || packetsRead == totalPackets)
                        {
                            double percentage = (double)packetsRead / totalPackets * 100;
                            Console.Write($"\rProgress: {percentage:F2}% | {packetsRead} / {totalPackets} packets    ");
                        }
                    }
                    catch (Exception ex) // Catch all exceptions to prevent the program from crashing on malformed packets
                    {
                        Console.WriteLine($"\nWarning: Skipping malformed packet due to error: {ex.Message}");
                        continue;
                    }
                }
                Console.WriteLine($"\rProgress: 100.00% | {packetsRead} / {totalPackets} packets    ");
            }
            Console.WriteLine("\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nAn error occurred while reading the file: {ex.Message}");
            return new List<TransportStreamPacket>();
        }

        return packets;
    }

    public void DisplayStats(List<TransportStreamPacket> packets)
    {
        if (packets == null || packets.Count == 0)
        {
            Console.WriteLine("No packets to display stats for.");
            return;
        }

        Console.WriteLine("--- Starting In-Memory Analysis ---");

        Console.Write("  -> Parsing PAT and PMT tables... ");
        var patPackets = packets.Where(p => p.Pid == 0).ToList();
        var patEntries = ParsePat(patPackets);

        // Get PMT PIDs from PAT and check if any packets exist for them.
        var pmtPidsFromPat = new HashSet<ushort>(patEntries.Select(e => e.PmtPid));
        var pmtPackets = packets.Where(p => pmtPidsFromPat.Contains(p.Pid)).ToList();

        // If no PMT packets are found via PAT, try a heuristic search.
        if (!pmtPackets.Any())
        {
            ushort heuristicPmtPid = FindPmtPidHeuristically(packets);
            if (heuristicPmtPid != 0)
            {
                pmtPackets = packets.Where(p => p.Pid == heuristicPmtPid).ToList();
                pmtPidsFromPat.Add(heuristicPmtPid); // Add to the set for the Is PMT check later
            }
        }

        var pmtComponentEntries = ParsePmt(pmtPackets);
        Console.WriteLine("Done.");

        Console.WriteLine("  -> Grouping and analyzing packet data in parallel...");

        // Use PLINQ (AsParallel) for parallel grouping and processing
        var sortedStats = packets.AsParallel()
            .GroupBy(p => p.Pid)
            .OrderBy(group => group.Key)
            .Select(group =>
            {
                // Find the first PMT component entry that matches this PID, if any
                var componentEntry = pmtComponentEntries.Values
                    .SelectMany(x => x)
                    .FirstOrDefault(e => e.ElementaryPid == group.Key);

                return new
                {
                    Pid = group.Key,
                    Count = group.Count(),
                    HasPayloadStart = group.Any(p => p.PayloadUnitStartIndicator),
                    ContinuityErrors = GetContinuityErrors(group.ToList()),
                    IsPat = group.Key == 0,
                    IsPmt = pmtPidsFromPat.Contains(group.Key),
                    // Use null-conditional operator to safely access StreamType, defaulting to 0 if not found
                    StreamType = componentEntry?.StreamType ?? 0
                };
            }).ToList(); // Materialize the list after parallel processing

        Console.WriteLine("\n  -> Generating formatted report...");

        Console.WriteLine($"\n--- Transport Stream Analysis for '{Path.GetFileName(_filePath)}' ---");
        Console.WriteLine($"Total Packets Found: {packets.Count}");
        Console.WriteLine($"Packet Size: {TransportStreamPacket.PacketSize} bytes\n");

        Console.WriteLine("{0,-10} {1,-15} {2,-20} {3,-20} {4,-10} {5,-10} {6,-15}",
            "PID", "Packet Count", "Payload Start", "Continuity Errors", "Is PAT", "Is PMT", "Stream Type");
        Console.WriteLine(new string('-', 120));

        foreach (var stat in sortedStats)
        {
            Console.WriteLine("{0,-10} {1,-15} {2,-20} {3,-20} {4,-10} {5,-10} {6,-15}",
                stat.Pid,
                stat.Count,
                stat.HasPayloadStart ? "Yes" : "No",
                stat.ContinuityErrors > 0 ? stat.ContinuityErrors.ToString() : "None",
                stat.IsPat ? "Yes" : "No",
                stat.IsPmt ? "Yes" : "No",
                stat.StreamType > 0 ? GetStreamTypeDescription(stat.StreamType) : "N/A");
        }
    }

    public int GetContinuityErrors(List<TransportStreamPacket> packets)
    {
        if (packets.Count <= 1) return 0;
        int errors = 0;
        for (int i = 1; i < packets.Count; i++)
        {
            if (packets[i].AdaptationFieldControl == 1 || packets[i].AdaptationFieldControl == 0) continue;
            byte expectedCC = (byte)((packets[i - 1].ContinuityCounter + 1) % 16);
            if (packets[i].ContinuityCounter != expectedCC)
            {
                errors++;
            }
        }
        return errors;
    }

    /// <summary>
    /// Parses Program Map Table (PMT) packets to find elementary streams for each program.
    /// </summary>
    /// <param name="pmtPackets">A list of Transport Stream packets containing PMT data.</param>
    /// <returns>A dictionary mapping Program Number to a list of its component streams.</returns>
    public Dictionary<ushort, List<PmtComponentEntry>> ParsePmt(List<TransportStreamPacket> pmtPackets)
    {
        var pmtComponentEntries = new Dictionary<ushort, List<PmtComponentEntry>>();

        if (!pmtPackets.Any())
        {
            return pmtComponentEntries;
        }

        var processedPids = new HashSet<ushort>();

        foreach (var packet in pmtPackets)
        {
            if (packet.PayloadUnitStartIndicator)
            {
                byte[] payload = packet.Payload;
                // Add null check for payload
                if (payload == null || payload.Length == 0) continue;

                int pointerField = payload[0]; // Get the pointer field
                int tableIdIndex = 1 + pointerField;

                if (tableIdIndex < payload.Length && payload[tableIdIndex] == 0x02) // PMT Table ID
                {
                    // Log the PMT PID if it's new
                    if (_loggedPmtPids.Add(packet.Pid))
                    {
                        Console.WriteLine($"      -> Found PMT on PID {packet.Pid}");
                    }

                    ushort programNumber = (ushort)((payload[tableIdIndex + 3] << 8) | payload[tableIdIndex + 4]);
                    int sectionLength = ((payload[tableIdIndex + 1] & 0x0F) << 8) | payload[tableIdIndex + 2];
                    int offset = tableIdIndex + 12; // Start after fixed header and program info length

                    ushort programInfoLength = (ushort)(((payload[tableIdIndex + 10] & 0x0F) << 8) | payload[tableIdIndex + 11]);
                    offset += programInfoLength;

                    List<PmtComponentEntry> currentPmtEntries = new List<PmtComponentEntry>();

                    while (offset < tableIdIndex + sectionLength - 4) // Section length includes CRC, so subtract 4 bytes for CRC32
                    {
                        byte streamType = payload[offset];
                        ushort elementaryPid = (ushort)(((payload[offset + 1] & 0x1F) << 8) | payload[offset + 2]);
                        ushort esInfoLength = (ushort)(((payload[offset + 3] & 0x0F) << 8) | payload[offset + 4]);

                        var entry = new PmtComponentEntry
                        {
                            ElementaryPid = elementaryPid,
                            StreamType = streamType
                        };

                        currentPmtEntries.Add(entry);

                        offset += 5 + esInfoLength;
                    }

                    if (!pmtComponentEntries.ContainsKey(programNumber))
                    {
                        pmtComponentEntries[programNumber] = new List<PmtComponentEntry>();
                    }

                    foreach (var entry in currentPmtEntries)
                    {
                        if (!pmtComponentEntries[programNumber].Any(e => e.ElementaryPid == entry.ElementaryPid))
                        {
                            pmtComponentEntries[programNumber].Add(entry);
                        }
                    }
                    processedPids.Add(packet.Pid); // Mark this PMT PID as processed
                }
            }
        }
        return pmtComponentEntries;
    }

    public void ExtractPidsPackets(List<ushort> pidsToExtract, string outputFileName, List<TransportStreamPacket> packets)
    {
        Console.WriteLine($"\n--- Extracting PIDs to '{outputFileName}' ---");
        Console.WriteLine($"PIDs to extract: {string.Join(", ", pidsToExtract)}");

        int packetsWritten = 0;

        using (var outputStream = new FileStream(outputFileName, FileMode.Create))
        {
            foreach (var packet in packets)
            {
                if (pidsToExtract.Contains(packet.Pid))
                {
                    outputStream.Write(packet.Data, 0, TransportStreamPacket.PacketSize);
                    packetsWritten++;
                }
            }
        }

        Console.WriteLine($"\nExtraction complete. Total packets written: {packetsWritten}");
    }

    public int FindPacketByTime(double targetSeconds, ushort pid, List<TransportStreamPacket> packets)
    {
        long targetTimestamp = (long)(targetSeconds * 90000); // Convert seconds to 90kHz clock ticks
        int scanLimit = packets.Count;

        for (int i = 0; i < scanLimit; i++)
        {
            var packet = packets[i];
            if (packet.Pid == pid && packet.PayloadUnitStartIndicator)
            {
                if ((packet.AdaptationFieldControl == 0x02 || packet.AdaptationFieldControl == 0x03) && packet.Payload.Length > 0)
                {
                    long? timestamp = null;

                    // Parse PCR (Program Clock Reference) from Adaptation Field
                    // Check adaptation field length and PCR flag (bit 4)
                    if (packet.Payload.Length > 0 && packet.Payload[0] > 0 && (packet.AdaptationFieldControl == 3 || packet.AdaptationFieldControl == 2))
                    {
                        var adaptationFieldLength = packet.Buffer[4];
                        if (adaptationFieldLength > 0 && packet.Buffer.Length > 5 && (packet.Buffer[5] & 0x10) != 0)
                        {
                            // A proper PCR check would need to parse the Adaptation Field.
                            // We will use a simplified check here.
                            if (adaptationFieldLength >= 6)
                            {
                                long pcrBase = ((long)packet.Buffer[5] << 25) | ((long)packet.Buffer[6] << 17) | ((long)packet.Buffer[7] << 9) | ((long)packet.Buffer[8] << 1) | ((long)packet.Buffer[9] >> 7);
                                timestamp = pcrBase;
                            }
                        }
                    }

                    if (timestamp.HasValue)
                    {
                        if (timestamp.Value >= targetTimestamp)
                        {
                            Console.WriteLine($"Found target time at packet {i} (PID: {pid}, Timestamp: {timestamp.Value})");
                            return i;
                        }
                    }
                }
            }
        }

        Console.WriteLine("Warning: Could not find the specified timestamp in the stream.");
        return -1; // Return -1 if not found
    }

    public void ExtractPidsPacketsInSegment(List<ushort> pidsToExtract, string outputFileName, List<TransportStreamPacket> packets, int startPacket, int endPacket)
    {
        Console.WriteLine($"\n--- Extracting PIDs to '{outputFileName}' ---");
        Console.WriteLine($"PIDs to extract: {string.Join(", ", pidsToExtract)}");
        Console.WriteLine($"Segment: Packet {startPacket} to {endPacket}");

        int packetsWritten = 0;

        using (var outputStream = new FileStream(outputFileName, FileMode.Create))
        {
            for (int i = startPacket; i < packets.Count && i <= endPacket; i++)
            {
                var packet = packets[i];
                if (pidsToExtract.Contains(packet.Pid))
                {
                    outputStream.Write(packet.Data, 0, TransportStreamPacket.PacketSize);
                    packetsWritten++;
                }
            }
        }

        Console.WriteLine($"\nExtraction complete. Total packets written: {packetsWritten}");
    }

    public List<PatEntry> ParsePat(List<TransportStreamPacket> patPackets)
    {
        var patEntries = new List<PatEntry>();

        if (!patPackets.Any())
        {
            Console.WriteLine("\n  -> No PAT packets (PID 0) found in the stream.");
            return patEntries;
        }

        Console.WriteLine("\n  -> Parsing PAT sections from PID 0 (repeated entries suppressed)...");

        foreach (var packet in patPackets)
        {
            if (packet.PayloadUnitStartIndicator)
            {
                byte[] payload = packet.Payload;
                // Add null check for payload
                if (payload == null || payload.Length == 0) continue;

                int pointerField = payload[0];
                int tableIdIndex = 1 + pointerField;

                if (tableIdIndex < payload.Length && payload[tableIdIndex] == 0x00) // PAT Table ID
                {
                    int offset = tableIdIndex + 8;
                    int sectionLength = ((payload[tableIdIndex + 1] & 0x0F) << 8) | payload[tableIdIndex + 2];

                    while (offset < tableIdIndex + sectionLength - 4) // Subtract 4 bytes for CRC32
                    {
                        ushort programNumber = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                        ushort pmtPid = (ushort)(((payload[offset + 2] & 0x1F) << 8) | payload[offset + 3]);

                        var currentEntry = new PatEntry { ProgramNumber = programNumber, PmtPid = pmtPid };

                        // Use the hash set to check for and add new entries
                        if (_loggedPatEntries.Add(currentEntry))
                        {
                            Console.WriteLine($"      -> Found PAT entry: Program Number = {programNumber}, PMT PID = {pmtPid}");
                        }

                        if (programNumber != 0) // Program number 0 is the NIT PID, we want programs
                        {
                            if (!patEntries.Any(e => e.ProgramNumber == programNumber))
                            {
                                patEntries.Add(currentEntry);
                            }
                        }
                        offset += 4;
                    }
                }
            }
        }

        return patEntries;
    }

    public ushort FindPmtPidHeuristically(List<TransportStreamPacket> packets)
    {
        Console.WriteLine("\n  -> PAT did not contain a valid PMT PID. Searching heuristically for a PMT (Table ID 0x02)...");

        foreach (var packet in packets)
        {
            if (packet.PayloadUnitStartIndicator && packet.Pid != 0)
            {
                byte[] payload = packet.Payload;
                // Add null check for payload
                if (payload == null || payload.Length == 0) continue;

                int pointerField = payload[0];
                int tableIdIndex = 1 + pointerField;

                // Check if the payload starts with the PMT Table ID (0x02) after the pointer field
                if (tableIdIndex < packet.Payload.Length && packet.Payload[tableIdIndex] == 0x02)
                {
                    Console.WriteLine($"      -> Heuristically found a PMT on PID {packet.Pid}. Using this PID.");
                    return packet.Pid;
                }
            }
        }

        Console.WriteLine("      -> No PMT found heuristically. Extraction cannot proceed.");
        return 0; // Return 0 to indicate failure
    }

    public void ExtractPidPackets(ushort pid, string outputFilePath, List<TransportStreamPacket> packets)
    {
        Console.WriteLine($"\n--- Extracting PID {pid} packets to '{outputFilePath}' ---");

        var packetsToExtract = packets.Where(p => p.Pid == pid).ToList();
        int totalPackets = packetsToExtract.Count;
        int packetsWritten = 0;

        if (totalPackets == 0)
        {
            Console.WriteLine($"Warning: No packets found for PID {pid}. No file will be created.");
            return;
        }

        try
        {
            using (var fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                Console.Write("Writing packets: 0.00%");

                foreach (var packet in packetsToExtract)
                {
                    fs.Write(packet.Data, 0, TransportStreamPacket.PacketSize);
                    packetsWritten++;

                    if (packetsWritten % 1000 == 0 || packetsWritten == totalPackets)
                    {
                        double percentage = (double)packetsWritten / totalPackets * 100;
                        Console.Write($"\rWriting packets: {percentage:F2}% | {packetsWritten} / {totalPackets} packets    ");
                    }
                }

                Console.Write($"\rWriting packets: 100.00% | {packetsWritten} / {totalPackets} packets    ");
            }
            Console.WriteLine("\nExtraction complete.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nAn error occurred while writing the file: {ex.Message}");
        }
    }

    public void ExtractProgramPackets(ushort programNumber, string outputFilePath, List<TransportStreamPacket> packets)
    {
        Console.WriteLine($"\n--- Extracting Program {programNumber} packets to '{outputFilePath}' ---");

        var patPackets = packets.Where(p => p.Pid == 0).ToList();
        var patEntries = ParsePat(patPackets);

        // FirstOrDefault returns a default struct if not found, where ProgramNumber will be 0
        var patEntry = patEntries.FirstOrDefault(e => e.ProgramNumber == programNumber);

        ushort pmtPid;

        if (patEntry.PmtPid == 0) // Check if the PMT PID is valid
        {
            Console.WriteLine($"Error: Program {programNumber} not found in the PAT. Attempting heuristic search for PMT...");
            pmtPid = FindPmtPidHeuristically(packets);
            if (pmtPid == 0)
            {
                Console.WriteLine("Error: Extraction aborted as no PMT was found.");
                return;
            }
        }
        else
        {
            pmtPid = patEntry.PmtPid;
        }

        var pmtPackets = packets.Where(p => p.Pid == pmtPid).ToList();
        var pmtInfo = ParsePmt(pmtPackets);

        var elementaryPids = new HashSet<ushort>();
        ushort pcrPid = 0;

        if (pmtInfo.ContainsKey(programNumber))
        {
            foreach (var entry in pmtInfo[programNumber])
            {
                elementaryPids.Add(entry.ElementaryPid);
            }

            var pmtHeaderPacket = pmtPackets.FirstOrDefault(p => p.PayloadUnitStartIndicator);
            // This check is now correct for a struct: it checks if the packet has a valid sync byte.
            if (pmtHeaderPacket.SyncByte == 0x47 && pmtHeaderPacket.Payload.Length > 8)
            {
                // PCR PID is located at bytes 8 and 9 of the PMT payload.
                pcrPid = (ushort)(((pmtHeaderPacket.Payload[8] & 0x1F) << 8) | pmtHeaderPacket.Payload[9]);
            }
        }
        else
        {
            Console.WriteLine($"Error: PMT for program {programNumber} not found. Extraction aborted.");
            return;
        }

        var pidsToExtract = new HashSet<ushort>
        {
            0,      // PAT PID
            pmtPid  // PMT PID
        };

        foreach (var pid in elementaryPids)
        {
            pidsToExtract.Add(pid);
        }

        if (pcrPid > 0)
        {
            pidsToExtract.Add(pcrPid);
        }

        Console.WriteLine($"  -> Identified PIDs for extraction: {string.Join(", ", pidsToExtract)}");

        var packetsToExtract = packets.Where(p => pidsToExtract.Contains(p.Pid)).ToList();
        int totalPackets = packetsToExtract.Count;
        int packetsWritten = 0;

        if (totalPackets == 0)
        {
            Console.WriteLine($"Warning: No packets found for the selected program. No file will be created.");
            return;
        }

        try
        {
            using (var fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                Console.Write("  -> Writing packets: 0.00%");

                foreach (var packet in packetsToExtract)
                {
                    fs.Write(packet.Data, 0, TransportStreamPacket.PacketSize);
                    packetsWritten++;

                    if (packetsWritten % 1000 == 0 || packetsWritten == totalPackets)
                    {
                        double percentage = (double)packetsWritten / totalPackets * 100;
                        Console.Write($"\r  -> Writing packets: {percentage:F2}% | {packetsWritten} / {totalPackets} packets    ");
                    }
                }

                Console.Write($"\r  -> Writing packets: 100.00% | {packetsWritten} / {totalPackets} packets    ");
            }
            Console.WriteLine("\nExtraction complete.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nAn error occurred while writing the file: {ex.Message}");
        }
    }

    /// <summary>
    /// Finds the program with the longest elementary stream (video or audio) and returns its program number.
    /// </summary>
    public ushort? GetLongestProgram(List<TransportStreamPacket> packets)
    {
        Console.WriteLine("  -> Identifying the longest program...");

        Console.WriteLine("  -> Phase 1: Parsing PAT and PMT tables to identify elementary streams...");
        var patPackets = packets.Where(p => p.Pid == 0 && p.PayloadUnitStartIndicator).ToList();
        var patEntries = ParsePat(patPackets);

        // Get all PMT PIDs from the PAT entries
        var pmtPids = patEntries.Select(e => e.PmtPid).ToList();
        var pmtPackets = packets.Where(p => pmtPids.Contains(p.Pid)).ToList();

        // If no PMT packets are found from the PAT, try a heuristic search for a PMT.
        if (!pmtPackets.Any())
        {
            ushort heuristicPmtPid = FindPmtPidHeuristically(packets);
            if (heuristicPmtPid != 0)
            {
                pmtPids.Add(heuristicPmtPid);
                pmtPackets = packets.Where(p => p.Pid == heuristicPmtPid).ToList();
            }
        }

        var pmtInfo = ParsePmt(pmtPackets);

        // Flatten the list of all elementary stream PIDs from all programs
        var allElementaryPids = pmtInfo.Values.SelectMany(list => list).Select(c => c.ElementaryPid).Distinct().ToList();

        // Count packets for each elementary stream PID
        Console.WriteLine("  -> Phase 2: Counting packets for each elementary stream PID...");
        var pidPacketCounts = new Dictionary<ushort, int>();

        int packetsProcessed = 0;
        int totalPackets = packets.Count;

        foreach (var packet in packets)
        {
            if (allElementaryPids.Contains(packet.Pid))
            {
                if (pidPacketCounts.ContainsKey(packet.Pid))
                {
                    pidPacketCounts[packet.Pid]++;
                }
                else
                {
                    pidPacketCounts[packet.Pid] = 1;
                }
            }

            packetsProcessed++;
            if (packetsProcessed % 50000 == 0 || packetsProcessed == totalPackets)
            {
                double percentage = (double)packetsProcessed / totalPackets * 100;
                Console.Write($"\r    -> Progress: {percentage:F2}% | {packetsProcessed} / {totalPackets} packets");
            }
        }
        Console.WriteLine(); // Newline after progress bar

        // Find the elementary stream with the most packets
        Console.WriteLine("  -> Phase 3: Finding the longest stream and its program...");
        var longestStreamPid = pidPacketCounts.OrderByDescending(kv => kv.Value).FirstOrDefault().Key;

        if (longestStreamPid != 0)
        {
            // Find the program number associated with the longest stream PID
            foreach (var entry in pmtInfo)
            {
                if (entry.Value.Any(c => c.ElementaryPid == longestStreamPid))
                {
                    Console.WriteLine($"  -> Identified Program {entry.Key} (PID {longestStreamPid}) as having the longest stream with {pidPacketCounts[longestStreamPid]} packets.");
                    return entry.Key;
                }
            }
        }

        Console.WriteLine("  -> No elementary stream was found to be the longest.");
        return null;
    }

    public string GetStreamTypeDescription(byte streamType)
    {
        switch (streamType)
        {
            case 0x01: return "MPEG-1 Video";
            case 0x02: return "MPEG-2 Video";
            case 0x03: return "MPEG-1 Audio";
            case 0x04: return "MPEG-2 Audio";
            case 0x06: return "PES private data/AC-3";
            case 0x0F: return "MPEG-2 AAC Audio";
            case 0x1B: return "AVC (H.264) Video";
            case 0x24: return "HEVC (H.265) Video";
            case 0x81: return "AC-3 Audio";
            case 0x86: return "DTS Audio";
            case 0x0D: return "SCTE-35 Data";
            default: return $"Unknown (0x{streamType:X2})";
        }
    }

    /// <summary>
    /// Joins a list of transport stream files into a single output file.
    /// </summary>
    /// <param name="filePaths">The list of input file paths to join.</param>
    /// <param name="outputFilePath">The path for the output joined file.</param>
    public void JoinTransportStreams(List<string> filePaths, string outputFilePath)
    {
        Console.WriteLine($"\n--- Joining Transport Stream Files to '{outputFilePath}' ---");
        Console.WriteLine($"Input files: {string.Join(", ", filePaths)}");

        int totalPacketsWritten = 0;

        try
        {
            using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                foreach (var filePath in filePaths)
                {
                    if (File.Exists(filePath))
                    {
                        Console.WriteLine($"  -> Processing file: {Path.GetFileName(filePath)}");
                        using (var inputStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                        {
                            byte[] buffer = new byte[TransportStreamPacket.PacketSize];
                            int bytesRead;

                            while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                if (bytesRead == TransportStreamPacket.PacketSize)
                                {
                                    outputStream.Write(buffer, 0, bytesRead);
                                    totalPacketsWritten++;
                                }
                                else
                                {
                                    Console.WriteLine($"    -> Warning: Incomplete packet ({bytesRead} bytes) at the end of {Path.GetFileName(filePath)}.");
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"  -> Warning: File not found and skipped: {Path.GetFileName(filePath)}");
                    }
                }
            }
            Console.WriteLine($"\nJoining complete. Total packets written: {totalPacketsWritten}.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nAn error occurred during file joining: {ex.Message}");
        }
    }

    /// <summary>
    /// Extracts a time segment from the stream based on a time string (e.g., "mm:ss-mm:ss").
    /// </summary>
    public void ExtractTimeSegment(string timeSegment, ushort? forcedPmtPid, string outputFile, List<TransportStreamPacket> packets)
    {
        Console.WriteLine($"\n--- Extracting time segment '{timeSegment}' to '{outputFile}' ---");

        var timeParts = timeSegment.Split('-');
        if (timeParts.Length != 2)
        {
            Console.WriteLine("Error: Invalid time segment format. Please use 'mm:ss-mm:ss'. Extraction aborted.");
            return;
        }

        double startTime = ParseTime(timeParts[0]);
        double endTime = ParseTime(timeParts[1]);

        if (startTime < 0 || endTime < 0 || startTime >= endTime)
        {
            Console.WriteLine("Error: Invalid start or end time. Extraction aborted.");
            return;
        }

        // 1. Find the PMT PID.
        ushort pmtPid;
        if (forcedPmtPid.HasValue)
        {
            pmtPid = forcedPmtPid.Value;
        }
        else
        {
            var patPackets = packets.Where(p => p.Pid == 0).ToList();
            var patEntries = ParsePat(patPackets);
            var patEntry = patEntries.FirstOrDefault(e => e.ProgramNumber != 0);
            if (patEntry.PmtPid == 0)
            {
                Console.WriteLine("Error: Could not find a program in the PAT. Use -pmtpid to specify it manually. Extraction aborted.");
                return;
            }
            pmtPid = patEntry.PmtPid;
        }

        // 2. Find the PCR PID from the PMT.
        var pmtPackets = packets.Where(p => p.Pid == pmtPid).ToList();
        var pmtInfo = ParsePmt(pmtPackets);
        ushort pcrPid = 0;

        // Assuming a single program for simplicity. You might need to select a program first.
        var programEntry = pmtInfo.Values.FirstOrDefault();
        if (programEntry != null)
        {
            var pmtHeaderPacket = pmtPackets.FirstOrDefault(p => p.PayloadUnitStartIndicator);
            // The comparison against 'null' is removed here, as TransportStreamPacket is a struct.
            if (pmtHeaderPacket.SyncByte == 0x47 && pmtHeaderPacket.Payload.Length > 8)
            {
                // PCR PID is located at bytes 8 and 9 of the PMT payload.
                pcrPid = (ushort)(((pmtHeaderPacket.Payload[8] & 0x1F) << 8) | pmtHeaderPacket.Payload[9]);
            }
        }

        if (pcrPid == 0)
        {
            Console.WriteLine("Error: Could not find the PCR PID in the PMT. Extraction aborted.");
            return;
        }

        // 3. Find start and end packets based on time.
        Console.WriteLine($"  -> Searching for start time {timeParts[0]}...");
        int startPacketIndex = FindPacketByTime(startTime, pcrPid, packets);
        Console.WriteLine($"  -> Searching for end time {timeParts[1]}...");
        int endPacketIndex = FindPacketByTime(endTime, pcrPid, packets);

        if (startPacketIndex == -1 || endPacketIndex == -1)
        {
            Console.WriteLine("Error: Could not find the start or end timestamp in the stream. Extraction aborted.");
            return;
        }

        // 4. Determine which PIDs to extract (all PIDs for the program).
        var pidsToExtract = new HashSet<ushort> { 0, pmtPid, pcrPid };
        if (programEntry != null)
        {
            foreach (var component in programEntry)
            {
                pidsToExtract.Add(component.ElementaryPid);
            }
        }

        // 5. Extract the segment.
        ExtractPidsPacketsInSegment(pidsToExtract.ToList(), outputFile, packets, startPacketIndex, endPacketIndex);
    }

    /// <summary>
    /// Helper to parse a "mm:ss" time string into seconds.
    /// </summary>
    private static double ParseTime(string timeString)
    {
        var parts = timeString.Split(':');
        if (parts.Length == 2 && int.TryParse(parts[0], out int minutes) && int.TryParse(parts[1], out int seconds))
        {
            return (minutes * 60) + seconds;
        }
        return -1; // Indicate failure
    }
}