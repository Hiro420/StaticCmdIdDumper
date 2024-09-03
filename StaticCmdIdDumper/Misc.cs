using System;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Text;

namespace PE_Parser;

public class Misc
{
    // read_str(): reads a 'count' of characters from a file
    // arguments: StreamReader to read from, count of characters to read
    // returns: string of characters.
    public static string ReadStr(StreamReader inStream, int count)
    {
        char[] chArray = new char[count];
        inStream.Read(chArray, 0, count);
        return new string(chArray);
    }

    // read8_le(): reads an 8bit integer
    // arguments: a StreamReader to read from
    // return: an 8 bit integer
    public static byte Read8Le(StreamReader inStream)
    {
        return (byte)inStream.Read();
    }

    // read16_le(): reads a 16bit little-endian integer
    // arguments: a StreamReader to read from
    // return: a 16 bit integer
    public static ushort Read16Le(StreamReader inStream)
    {
        ushort value = (byte)inStream.Read();
        value |= (ushort)(inStream.Read() << 8);
        return value;
    }

    // read32_le(): reads a 32bit little-endian integer
    // arguments: a StreamReader to read from
    // return: a 32 bit integer
    public static uint Read32Le(StreamReader inStream)
    {
        uint value = (byte)inStream.Read();
        value |= (uint)(inStream.Read() << 8);
        value |= (uint)(inStream.Read() << 16);
        value |= (uint)(inStream.Read() << 24);
        return value;
    }

    // read64_le(): reads a 64bit little-endian integer
    // arguments: a StreamReader to read from
    // return: a 64 bit integer
    public static ulong Read64Le(StreamReader inStream)
    {
        ulong value = (byte)inStream.Read();
        value |= ((ulong)inStream.Read() << 8);
        value |= ((ulong)inStream.Read() << 16);
        value |= ((ulong)inStream.Read() << 24);
        value |= ((ulong)inStream.Read() << 32);
        value |= ((ulong)inStream.Read() << 40);
        value |= ((ulong)inStream.Read() << 48);
        value |= ((ulong)inStream.Read() << 56);
        return value;
    }

    // print_sections(): prints pe sections info
    // arguments: a dos_header_t object
    // return: none
    public static void PrintSections(PEHeader.DosHeader dosHeader)
    {
        PEHeader.SectionTable[]? sections = dosHeader.section_table;
        Console.WriteLine("\nSections: ");

        for (int idx = 0; idx < dosHeader.pe.numberOfSections; idx++)
        {
            Console.WriteLine($"   Name: {sections![idx].name}");
            Console.WriteLine($"       VirtualAddress:        {sections[idx].virtualAddr:X}");
            Console.WriteLine($"       VirtualSize:           {sections[idx].virtualSize:X}");
            Console.WriteLine($"       SizeOfRawData:         {sections[idx].sizeOfRawData:X}");
            Console.WriteLine($"       PointerToRawData:      {sections[idx].ptrToRawData:X}");
            Console.WriteLine($"       PointerToRelocations:  {sections[idx].ptrToReloc:X}");
            Console.WriteLine($"       PointerToLineNumbers:  {sections[idx].ptrToLineNum:X}");
            Console.WriteLine($"       NumberOfRelocations:   {sections[idx].numberOfReloc:X}");
            Console.WriteLine($"       NumberOfLineNumbers:   {sections[idx].numberOfLineNum:X}");
            Console.WriteLine($"       characteristics:       {sections[idx].characteristics:X}");
            PEHeader.PrintSectionCharacteristics(sections[idx].characteristics);
        }
    }

    // load_file(): loads and reads pe files in current directory
    // arguments: integer representing argument count, and a string array
    // return: none
    public static void LoadFile(int argc, string[] argv)
    {
        for (int idx = 1; idx <= argc; idx++)
        {
            using (FileStream? fs = new FileStream(argv[idx-1], FileMode.Open, FileAccess.Read))
            {
                if (fs == null)
                {
                    Console.WriteLine($"Can't open '{argv[idx]}' file, exiting");
                    continue;
                }

                using (BinaryReader? reader = new BinaryReader(fs))
                {
                    PEHeader.DosHeader dosHeader = new PEHeader.DosHeader();

                    // read headers
                    PEHeader.ReadDos(reader, ref dosHeader);
                    PEHeader.ReadPe(reader, ref dosHeader);

                    // making sure we have a valid/standard pe file
                    if (dosHeader.pe.signature != 0x4550)
                    {
                        Console.WriteLine("invalid pe signature, file is likely corrupt pe, or not a valid pe file.");
                        return;
                    }

                    PEHeader.ReadDataDir(reader, ref dosHeader);
                    PEHeader.ReadSections(reader, ref dosHeader);
                    PEHeader.ReadDataOffset(ref dosHeader);
                    PEHeader.ReadExportDir(reader, ref dosHeader);
                    PEHeader.ReadImportDir(reader, ref dosHeader);

                    // test printing information
                    Console.WriteLine($"Parsing File: {argv[idx-1]} \n");

                    PrintHeaders(ref dosHeader);
                    PrintDataTables(ref dosHeader);
                    PrintSections(dosHeader);
                    PrintExports(ref dosHeader);
                    PrintImports(ref dosHeader);

                    // cleanup
                    PEHeader.Cleanup(ref dosHeader);
                }
            }
        }
    }

    public static PEHeader.SectionTable GetBaseAdd(string argv)
    {
        using (FileStream? fs = new FileStream(argv, FileMode.Open, FileAccess.Read))
        {
            if (fs == null)
            {
                Console.WriteLine($"Can't open '{argv}' file, exiting");
                Environment.Exit(1);
            }

            using (BinaryReader? reader = new BinaryReader(fs))
            {
                PEHeader.DosHeader dosHeader = new PEHeader.DosHeader();

                // read headers
                PEHeader.ReadDos(reader, ref dosHeader);
                PEHeader.ReadPe(reader, ref dosHeader);

                // making sure we have a valid/standard pe file
                if (dosHeader.pe.signature != 0x4550)
                {
                    Console.WriteLine("invalid pe signature, file is likely corrupt pe, or not a valid pe file.");
                    Environment.Exit(1);
                }

                PEHeader.ReadDataDir(reader, ref dosHeader);
                PEHeader.ReadSections(reader, ref dosHeader);
                PEHeader.ReadDataOffset(ref dosHeader);
                PEHeader.ReadExportDir(reader, ref dosHeader);
                PEHeader.ReadImportDir(reader, ref dosHeader);

                // test printing information

                // PEHeader.Cleanup(ref dosHeader);
                PEHeader.SectionTable[]? sections = dosHeader.section_table;

                for (int idx = 0; idx < dosHeader.pe.numberOfSections; idx++)
                {
                    if (sections![idx].name != "il2cpp")
                    {
                        continue;
                    }
                    return sections[idx];
                }
            }

            // Default
            return new PEHeader.SectionTable();
        }
    }

    private static ulong ImageBase(ref PEHeader.DosHeader dosHeader)
    {
        return dosHeader.pe.optionalHeader.imageBase - 1;
    }

    // print_headers(): prints the values of a DOS header object
    // arguments: a dos_header_t object
    // return: none
    public static void PrintHeaders(ref PEHeader.DosHeader dosHeader)
    {
        Console.WriteLine($"magic bytes: \t\t{(char)(0xff & dosHeader.magic)}{(char)(dosHeader.magic >> 8)}");
        Console.WriteLine($"pe Offset    \t\t{dosHeader.e_lfanew:X}");

        Console.WriteLine("\nPE header information");
        Console.WriteLine($" signature:   \t\t0x{dosHeader.pe.signature:X} {(char)(0xff & dosHeader.pe.signature)}{(char)(0xff & (dosHeader.pe.signature >> 8))} ");
        Console.Write(" Machine:  \t\t");
        PEHeader.PrintMachine(dosHeader.pe.machine);
        Console.WriteLine($" Sections: \t\t{dosHeader.pe.numberOfSections}");
        Console.WriteLine($" Time Stamp: \t\t0x{dosHeader.pe.timeStamp:X}");
        Console.WriteLine($" Symbol Table Pointer:  0x{dosHeader.pe.symTablePtr:X}");
        Console.WriteLine($" Symbols:               {dosHeader.pe.numberOfSym}");
        Console.WriteLine($" optionalHeader Size:    {dosHeader.pe.optionalHeaderSize} (0x{dosHeader.pe.optionalHeaderSize:X})");
        Console.WriteLine($" characteristics:       0x{dosHeader.pe.characteristics:X}");
        PEHeader.PrintPeCharacteristics(dosHeader.pe.characteristics);

        Console.WriteLine("\nOptional Header");
        Console.Write("magic:      ");
        PEHeader.PrintMagic(dosHeader.pe.optionalHeader.magic);
        Console.WriteLine($"MajorLinkerVersion:      0x{dosHeader.pe.optionalHeader.majorLinkerVer:X}");
        Console.WriteLine($"MinorLinkerVersion:      0x{dosHeader.pe.optionalHeader.minorLinkerVer:X}");
        Console.WriteLine($"SizeOfCode:              0x{dosHeader.pe.optionalHeader.sizeOfCode:X}");
        Console.WriteLine($"SizeOfInitializedData:   0x{dosHeader.pe.optionalHeader.sizeOfInitializedData:X}");
        Console.WriteLine($"SizeOfUninitializedData: 0x{dosHeader.pe.optionalHeader.sizeOfUninitializedData:X}");
        Console.WriteLine($"EntryPoint:              0x{dosHeader.pe.optionalHeader.entryPoint:X}");
        Console.WriteLine($"BaseOfCode:              0x{dosHeader.pe.optionalHeader.baseOfCode:X}");
        if (dosHeader.pe.optionalHeader.magic == 0x10b)
        {
            Console.WriteLine($"BaseOfData:              0x{dosHeader.pe.optionalHeader.baseOfData:X}");
        }
        Console.WriteLine($"ImageBase:               {dosHeader.pe.optionalHeader.imageBase-1:X}");
        Console.WriteLine($"SectionAlignment:        0x{dosHeader.pe.optionalHeader.sectionAlignment:X}");
        Console.WriteLine($"FileAlignment:           0x{dosHeader.pe.optionalHeader.fileAlignment:X}");
        Console.WriteLine($"MajorOSVersion:          0x{dosHeader.pe.optionalHeader.majorOSVer:X}");
        Console.WriteLine($"MinorOSVersion:          0x{dosHeader.pe.optionalHeader.minorOSVer:X}");
        Console.WriteLine($"MajorImageVersion:       0x{dosHeader.pe.optionalHeader.majorImageVer:X}");
        Console.WriteLine($"MinorImageVersion:       0x{dosHeader.pe.optionalHeader.minorImageVer:X}");
        Console.WriteLine($"MajorSubsysVersion:      0x{dosHeader.pe.optionalHeader.majorSubsystemVer:X}");
        Console.WriteLine($"MinorSubsysVersion:      0x{dosHeader.pe.optionalHeader.minorSubsystemVer:X}");
        Console.WriteLine($"Win32VersionValue:       0x{dosHeader.pe.optionalHeader.win32VersionVal:X}");
        Console.WriteLine($"SizeOfImage:             0x{dosHeader.pe.optionalHeader.sizeOfImage:X}");
        Console.WriteLine($"SizeOfHeaders:           0x{dosHeader.pe.optionalHeader.sizeOfHeaders:X}");
        Console.WriteLine($"CheckSum:                0x{dosHeader.pe.optionalHeader.checkSum:X}");
        Console.Write("Subsystem:             ");
        PEHeader.PrintSubsystem(dosHeader.pe.optionalHeader.subsystem);
        Console.WriteLine("DllCharacteristics:           ");
        PEHeader.PrintDllCharacteristics(dosHeader.pe.optionalHeader.dllCharacteristics);

        Console.WriteLine($"SizeOfStackReserve:      {dosHeader.pe.optionalHeader.sizeOfStackReserve:X}");
        Console.WriteLine($"SizeOfStackCommit:       {dosHeader.pe.optionalHeader.sizeOfStackCommit:X}");
        Console.WriteLine($"SizeOfHeapReserve:       {dosHeader.pe.optionalHeader.sizeOfHeapReserve:X}");
        Console.WriteLine($"SizeOfHeapCommit:        {dosHeader.pe.optionalHeader.sizeOfHeapCommit:X}");

        Console.WriteLine($"LoaderFlags:             0x{dosHeader.pe.optionalHeader.loaderFlags:X}");
        Console.WriteLine($"NumberOfRvaAndSizes:     {dosHeader.pe.optionalHeader.numberOfRvaAndSizes}");
    }

    // print_dataTables(): prints a list of data tables in a pe file
    // arguments: a dos_header_t object
    // return: none
    public static void PrintDataTables(ref PEHeader.DosHeader dosHeader)
    {
        // Data Directories Types
        string[] dataTable = { "Export Table", "Import Table",
                               "Resource Table", "Exception Table",
                               "Certificate ", "Base Relocation",
                               "Debug Table", "Architecture",
                               "Global Ptr Table", "TLS Table",
                               "Load Config ", "Bound Import",
                               "Import Address", "Delay Import Desc.",
                               "CLR Runtime Header", "Reserved, must be zero" };

        uint offset, vAddress, sections, tables;
        sections = dosHeader.pe.numberOfSections;

        tables = dosHeader.pe.optionalHeader.numberOfRvaAndSizes;

        Console.WriteLine("\nData Tables: ");
        for (int idx = 0; idx < tables; idx++)
        {
            vAddress = dosHeader.dataDirectory![idx].virtualAddr;

            // skipping empty directories
            if (vAddress == 0) continue;

            Console.WriteLine($"  {dataTable[idx]}: ");

            offset = (uint)PEHeader.RvaToOffset(sections, vAddress, dosHeader.section_table!);

            Console.WriteLine($"     Address: 0x{vAddress:X} \tOffset: 0x{offset:X}");
            Console.WriteLine($"        Size: 0x{dosHeader.dataDirectory[idx].size:X} ");
        }
    }

    // print_exports(): prints a list of exports in a pe file
    // arguments: a dos_header_t object
    // return: none
    public static void PrintExports(ref PEHeader.DosHeader dosHeader)
    {
        Console.WriteLine("\nExport Directory ");
        Console.WriteLine($"    Flags:           0x{dosHeader.exportDir.exportFlags:X}");
        Console.WriteLine($"    TimeStamp:       0x{dosHeader.exportDir.timeStamp:X}");
        Console.WriteLine($"    MajorVersion:    0x{dosHeader.exportDir.majorVer:X}");
        Console.WriteLine($"    MinorVersion:    0x{dosHeader.exportDir.minorVer:X}");
        Console.WriteLine($"    Name RVA:        0x{dosHeader.exportDir.nameRVA:X}");
        Console.WriteLine($"    OrdinalBase:     0x{dosHeader.exportDir.ordinalBase:X}");
        Console.WriteLine($"    AddressTable Entries:  0x{dosHeader.exportDir.addrTableEntries:X}");
        Console.WriteLine($"    NumberOfNames:         0x{dosHeader.exportDir.numberOfNamePointers:X}");
        Console.WriteLine($"    ExportTable Entries:   0x{dosHeader.exportDir.exportAddrTableRVA:X}");
        Console.WriteLine($"    AddressOfNames:        0x{dosHeader.exportDir.namePtrRVA:X}");
        Console.WriteLine($"    OrdinalTable RVA:      0x{dosHeader.exportDir.ordinalTableRVA:X}");

        Console.WriteLine("\nExported functions: ");

        // skipping none IMAGE_FILE_DLL
        if ((dosHeader.pe.characteristics & 0x2000) == 0) return;

        for (int i = 0; i < dosHeader.exportDir.numberOfNamePointers; i++)
        {
            Console.WriteLine($"   {dosHeader.exportDir.exportAddr_name_t![i].names}");
        }
    }

    // print_imports(): prints a list of imports in a pe file
    // arguments: a dos_header_t object
    // return: none
    public static void PrintImports(ref PEHeader.DosHeader dosHeader)
    {
        uint? tableEntries;

        tableEntries = (dosHeader.dataDirectory![1].size / 20) - 1;
        Console.WriteLine("\nImport Directory ");

        for (uint idx = 0; idx < tableEntries; idx++)
        {
            Console.WriteLine($"  Import Lookup table RVA: {dosHeader.importDir![idx].importLookupTableRVA:X}");
            Console.WriteLine($"  Time Stamp:              {dosHeader.importDir[idx].timeStamp:X}");
            Console.WriteLine($"  Forwarder Chain:         {dosHeader.importDir[idx].forwarderChain:X}");
            Console.WriteLine($"  Name RVA:                {dosHeader.importDir[idx].nameRVA:X}");
            Console.WriteLine($"  Import Address table RVA: {dosHeader.importDir[idx].importAddressRVA:X}");
        }
    }
}

