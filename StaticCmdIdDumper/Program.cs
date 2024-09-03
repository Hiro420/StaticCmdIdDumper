using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace PE_Parser;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: StaticCmdIdDumper.exe <YuanShen.exe> <list.txt>");
            Environment.Exit(1);
        }

        Dictionary<string, int> packetIds = new();

        Dictionary<string, string> keyValuePairs = new Dictionary<string, string>();
        using (StreamReader reader = new StreamReader(args[1]))
        {
            string line;
            while ((line = reader.ReadLine()!) != null)
            {
                // Split the line by space
                string[] parts = line.Split(' ');
                if (parts.Length == 2)
                {
                    keyValuePairs[parts[0]] = parts[1];
                }
            }
        }

        // Get the il2cpp section VA from PEHeader.cs
        PEHeader.SectionTable il2cpp_section = Misc.GetBaseAdd(args[0]);
        if (il2cpp_section.virtualAddr == 0)
        {
            Console.WriteLine($"il2cpp section is fucked up, exiting...");
            Environment.Exit(1);
        }

        // Console.WriteLine($"Il2cpp section Base Address: {il2cpp_section.virtualAddr} (${il2cpp_section.virtualAddr:X})");


        foreach (var pair in keyValuePairs)
        {

            // I hate this line of code
            ulong CmdIDTestAddr = Convert.ToUInt64(pair.Value.Substring(2), 16);

            // 0xE31E660
            // PE_BaseAddress == 0x4000000

            // WHY DOES IT READ FROM 0xDB68060 in IDA
            // edit: okay its supposed to be POINTER TO RAW DATA+(RVA−VA of section start [il2cpp])

            // read 4 bytes of the file from the address and disassemble this shit

            var fileoffset = il2cpp_section.ptrToRawData + (CmdIDTestAddr - il2cpp_section.virtualAddr);

            // Console.WriteLine($"FileOffset: {fileoffset:x}");

            byte[] buffer = new byte[4];
            using (FileStream fs = new FileStream(args[0], FileMode.Open, FileAccess.Read))
            {
                fs.Seek((long)fileoffset, SeekOrigin.Begin);
                // Console.WriteLine($"Reading from {fileoffset:X8}");
                fs.Read(buffer, 0, 4);
            }

            /*
            foreach (byte b in buffer)
            {
                Console.WriteLine($"{b:x}");
            }
            */

            int cmdid = Disassembler.Disassemble(buffer);

            // Console.WriteLine($"cmdId: {cmdid}");

            // set pair.Key to be value of cmdid
            packetIds[pair.Key] = cmdid;
        }

        // Write the output to PacketIds.json
        string jsonString = JsonSerializer.Serialize(packetIds, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText("PacketIds.json", jsonString);
        Console.WriteLine("Done.");
    }
}

