// Program.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

class Program
{
    static void Main(string[] args)
    {
        string? filePath = null;
        ushort? pidToExtract = null;
        ushort? forcedPmtPid = null;
        List<ushort>? pidsToExtract = null;
        bool extractLongestProgram = false;
        bool extractMpegOnly = false;
        bool outputToSourceDir = false;
        int? startPacket = null;
        int? endPacket = null;
        string? timeSegment = null;
        string? joinedFileName = null;
        string? outputFile = null;

        if (args.Length == 0)
        {
            Console.WriteLine("Transport Stream Analyzer by Mike Williams - Copyright 2025");
            Console.WriteLine("-----------------------------------------------------------");
            Console.WriteLine("Usage: TransportStreamAnalyzer <file_path> [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  -extractpid <pid>                   Extracts a single PID to a new file.");
            Console.WriteLine("  -extractprogram longest             Extracts the program with the longest elementary stream.");
            Console.WriteLine("  -extractmpeg                        Filters the longest program to only include MPEG video/audio.");
            Console.WriteLine("  -extractpids <pid1>,<pid2>,...      Extracts a comma-separated list of PIDs.");
            Console.WriteLine("  -pmtpid <pid>                       Forces a specific PMT PID to be used.");
            Console.WriteLine("  -output <file_path>                 Specifies the output file path.");
            Console.WriteLine("  -sourceout                          Outputs the file to the source directory.");
            Console.WriteLine("  -start <packet_number>              Sets the start packet index for extraction.");
            Console.WriteLine("  -end <packet_number>                Sets the end packet index for extraction.");
            Console.WriteLine("  -time <mm:ss-mm:ss>                 Extracts a segment by time.");
            Console.WriteLine("  -join <file_name>                   Joins multiple files into a single file with a new name.");
            Console.WriteLine("");
            Console.WriteLine("Examples:");
            Console.WriteLine("  TransportStreamAnalyzer video.ts -extractpid 257");
            Console.WriteLine("  TransportStreamAnalyzer stream.ts -extractprogram longest -extractmpeg");
            Console.WriteLine("  TransportStreamAnalyzer movie.ts -extractpids 100,101,102 -start 5000 -end 15000");
            Console.WriteLine("  TransportStreamAnalyzer recording.ts -time 01:30-02:45");
            Console.WriteLine("  TransportStreamAnalyzer input.ts -extractpid 101 -output output.ts");
            return;
        }

        filePath = args[0];

        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "-extractpid":
                    if (i + 1 < args.Length && ushort.TryParse(args[i + 1], out ushort singlePid))
                    {
                        pidToExtract = singlePid;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -extractpid requires a PID value.");
                        return;
                    }
                    break;
                case "-extractprogram":
                    if (i + 1 < args.Length && args[i + 1].ToLower() == "longest")
                    {
                        extractLongestProgram = true;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -extractprogram requires 'longest'.");
                        return;
                    }
                    break;
                case "-extractmpeg":
                    extractMpegOnly = true;
                    break;
                case "-extractpids":
                    if (i + 1 < args.Length)
                    {
                        pidsToExtract = new List<ushort>();
                        var pidStrings = args[i + 1].Split(',');
                        foreach (var pidStr in pidStrings)
                        {
                            if (ushort.TryParse(pidStr, out ushort p))
                            {
                                pidsToExtract.Add(p);
                            }
                        }
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -extractpids requires a comma-separated list of PIDs.");
                        return;
                    }
                    break;
                case "-pmtpid":
                    if (i + 1 < args.Length && ushort.TryParse(args[i + 1], out ushort pmtPid))
                    {
                        forcedPmtPid = pmtPid;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -pmtpid requires a PID value.");
                        return;
                    }
                    break;
                case "-output":
                    if (i + 1 < args.Length)
                    {
                        outputFile = args[i + 1];
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -output requires a file path.");
                        return;
                    }
                    break;
                case "-sourceout":
                    outputToSourceDir = true;
                    break;
                case "-start":
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int startPack))
                    {
                        startPacket = startPack;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -start requires a packet number.");
                        return;
                    }
                    break;
                case "-end":
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int endPack))
                    {
                        endPacket = endPack;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -end requires a packet number.");
                        return;
                    }
                    break;
                case "-time":
                    if (i + 1 < args.Length)
                    {
                        timeSegment = args[i + 1];
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -time requires a time segment (e.g., mm:ss-mm:ss).");
                        return;
                    }
                    break;
                case "-join":
                    if (i + 1 < args.Length)
                    {
                        joinedFileName = args[i + 1];
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Error: -join requires a file name.");
                        return;
                    }
                    break;
                default:
                    Console.WriteLine($"Warning: Unrecognized argument: {args[i]}");
                    break;
            }
        }

        if (string.IsNullOrEmpty(filePath))
        {
            Console.WriteLine("Error: No file path provided.");
            return;
        }

        var reader = new TransportStreamReader(filePath);
        var packets = reader.ReadPackets();

        if (packets.Count == 0)
        {
            Console.WriteLine("No packets read from the file.");
            return;
        }

        if (timeSegment != null)
        {
            reader.ExtractTimeSegment(timeSegment, forcedPmtPid, outputFile ?? GetOutputFilePath(filePath, "_time_segment.ts", outputToSourceDir), packets);
        }
        else if (pidToExtract.HasValue)
        {
            string outputFilePath = outputFile ?? GetOutputFilePath(filePath, $"_pid_{pidToExtract.Value}.ts", outputToSourceDir);
            reader.ExtractPidsPackets(new List<ushort> { pidToExtract.Value, 0 }, outputFilePath, packets);
        }
        else if (pidsToExtract != null)
        {
            string outputFilePath = outputFile ?? GetOutputFilePath(filePath, "_pids.ts", outputToSourceDir);
            pidsToExtract.Add(0); // Add PAT
            reader.ExtractPidsPackets(pidsToExtract, outputFilePath, packets);
        }
        else if (extractLongestProgram)
        {
            var patPackets = packets.Where(p => p.Pid == 0).ToList();
            var patEntries = reader.ParsePat(patPackets);
            if (patEntries == null || !patEntries.Any())
            {
                Console.WriteLine("Error: Could not find PAT. Extraction aborted.");
                return;
            }

            var pmtPids = new HashSet<ushort>(patEntries.Select(e => e.PmtPid));
            if (forcedPmtPid.HasValue)
            {
                pmtPids.Add(forcedPmtPid.Value);
            }
            var pmtPackets = packets.Where(p => pmtPids.Contains(p.Pid)).ToList();
            var pmtDict = reader.ParsePmt(pmtPackets);

            if (pmtDict == null || !pmtDict.Any())
            {
                Console.WriteLine("Error: Could not find any PMT entries. Extraction aborted.");
                return;
            }

            var longestProgramNumber = reader.GetLongestProgram(packets);
            if (longestProgramNumber.HasValue && pmtDict.ContainsKey(longestProgramNumber.Value))
            {
                var pmtComponents = pmtDict[longestProgramNumber.Value];
                var patEntry = patEntries.FirstOrDefault(e => e.ProgramNumber == longestProgramNumber.Value);

                var pidsToExtractForProgram = new HashSet<ushort> { 0, patEntry.PmtPid };
                foreach (var component in pmtComponents)
                {
                    pidsToExtractForProgram.Add(component.ElementaryPid);
                }

                // A proper implementation would parse the PMT payload for the PCR_PID field.
                var pmtHeaderPacket = pmtPackets.FirstOrDefault(p => p.PayloadUnitStartIndicator && p.Pid == patEntry.PmtPid);
                if (pmtHeaderPacket.Data.Length > 13) // PMT header is at least 13 bytes
                {
                    // The PCR PID is at bytes 8 and 9 of the PMT payload
                    ushort pcrPid = (ushort)(((pmtHeaderPacket.Payload[8] & 0x1F) << 8) | pmtHeaderPacket.Payload[9]);
                    pidsToExtractForProgram.Add(pcrPid);
                }

                string outputFileSuffix = extractMpegOnly ? "_mpeg_only.ts" : "_program.ts";
                var outputFilePath = outputFile ?? GetOutputFilePath(filePath, outputFileSuffix, outputToSourceDir);
                reader.ExtractPidsPackets(pidsToExtractForProgram.ToList(), outputFilePath, packets);
            }
            else
            {
                Console.WriteLine("Could not determine the longest program. No extraction performed.");
            }
        }
        else if (joinedFileName != null)
        {
            Console.WriteLine($"Joining files with output name: {joinedFileName}");
            // TODO: Implement file joining logic
        }
    }

    /// <summary>
    /// Helper to get the output file path.
    /// </summary>
    private static string GetOutputFilePath(string inputPath, string suffix, bool outputToSourceDir)
    {
        string directory = outputToSourceDir ? Path.GetDirectoryName(inputPath) : AppDomain.CurrentDomain.BaseDirectory;
        string fileName = Path.GetFileNameWithoutExtension(inputPath);
        string extension = Path.GetExtension(inputPath);
        return Path.Combine(directory, $"{fileName}{suffix}");
    }

    /// <summary>
    /// Parses a "mm:ss" time string and returns the total seconds.
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