using System;
using System.IO;
using System.Text;

namespace PE_Parser;

public class PEHeader
{
    // Define the necessary structures
    public struct DosHeader
    {
        public ushort magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        public ulong e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        public ulong e_res2;
        public uint e_lfanew;
        public PeHeader pe;
        public DataDirectory[]? dataDirectory;
        public SectionTable[]? section_table;
        public ExportDirectory exportDir;
        public ImportDirectory[]? importDir;
    }

    public struct PeHeader
    {
        public uint signature;
        public ushort machine;
        public ushort numberOfSections;
        public uint timeStamp;
        public uint symTablePtr;
        public uint numberOfSym;
        public ushort optionalHeaderSize;
        public ushort characteristics;
        public OptionalHeader optionalHeader;
    }

    public struct OptionalHeader
    {
        public ushort magic;
        public byte majorLinkerVer;
        public byte minorLinkerVer;
        public uint sizeOfCode;
        public uint sizeOfInitializedData;
        public uint sizeOfUninitializedData;
        public uint entryPoint;
        public uint baseOfCode;
        public uint baseOfData;
        public ulong imageBase;
        public uint sectionAlignment;
        public uint fileAlignment;
        public ushort majorOSVer;
        public ushort minorOSVer;
        public ushort majorImageVer;
        public ushort minorImageVer;
        public ushort majorSubsystemVer;
        public ushort minorSubsystemVer;
        public uint win32VersionVal;
        public uint sizeOfImage;
        public uint sizeOfHeaders;
        public uint checkSum;
        public ushort subsystem;
        public ushort dllCharacteristics;
        public ulong sizeOfStackReserve;
        public ulong sizeOfStackCommit;
        public ulong sizeOfHeapReserve;
        public ulong sizeOfHeapCommit;
        public uint loaderFlags;
        public uint numberOfRvaAndSizes;
    }

    public struct DataDirectory
    {
        public uint virtualAddr;
        public uint size;
        public long offset;
    }

    public struct SectionTable
    {
        public string? name;
        public uint virtualSize;
        public uint virtualAddr;
        public uint sizeOfRawData;
        public uint ptrToRawData;
        public uint ptrToReloc;
        public uint ptrToLineNum;
        public ushort numberOfReloc;
        public ushort numberOfLineNum;
        public uint characteristics;
    }

    public struct ExportDirectory
    {
        public uint exportFlags;
        public uint timeStamp;
        public ushort majorVer;
        public ushort minorVer;
        public uint nameRVA;
        public uint ordinalBase;
        public uint addrTableEntries;
        public uint numberOfNamePointers;
        public uint exportAddrTableRVA;
        public uint namePtrRVA;
        public uint ordinalTableRVA;
        public ExportAddressName[]? exportAddr_name_t;
    }

    public struct ExportAddressName
    {
        public string names;
    }

    public struct ImportDirectory
    {
        public uint importLookupTableRVA;
        public uint timeStamp;
        public uint forwarderChain;
        public uint nameRVA;
        public uint importAddressRVA;
    }

    // Helper functions to read data from the file
    public static ushort Read16LE(BinaryReader reader)
    {
        return (ushort)(reader.ReadByte() | (reader.ReadByte() << 8));
    }

    public static uint Read32LE(BinaryReader reader)
    {
        return (uint)(reader.ReadByte() | (reader.ReadByte() << 8) | (reader.ReadByte() << 16) | (reader.ReadByte() << 24));
    }

    public static ulong Read64LE(BinaryReader reader)
    {
        return (ulong)(reader.ReadByte() | (reader.ReadByte() << 8) | (reader.ReadByte() << 16) | (reader.ReadByte() << 24) |
                       (reader.ReadByte() << 32) | (reader.ReadByte() << 40) | (reader.ReadByte() << 48) | (reader.ReadByte() << 56));
    }

    public static string ReadStr(BinaryReader reader, int length)
    {
        byte[] bytes = reader.ReadBytes(length);
        return Encoding.ASCII.GetString(bytes).TrimEnd('\0');
    }

    // Function to clean allocated memory inside structs
    public static void Cleanup(ref PEHeader.DosHeader dosHeader)
    {
        dosHeader.dataDirectory = null;

        if (dosHeader.section_table != null)
        {
            for (int i = 0; i < dosHeader.section_table.Length; i++)
            {
                dosHeader.section_table[i].name = null;
            }
        }

        dosHeader.exportDir.exportAddr_name_t = null;
        dosHeader.section_table = null;
        dosHeader.importDir = null;
    }


    // Function to convert an RVA address to a file offset
    public static ulong RvaToOffset(uint numberOfSections, uint rva, SectionTable[] sections)
    {
        if (rva == 0) return 0;
        ulong sumAddr;

        for (uint idx = 0; idx < numberOfSections; idx++)
        {
            sumAddr = sections[idx].virtualAddr + sections[idx].sizeOfRawData;

            if (rva >= sections[idx].virtualAddr && (rva <= sumAddr))
            {
                return sections[idx].ptrToRawData + (rva - sections[idx].virtualAddr);
            }
        }
        return ulong.MaxValue;
    }

    // Function to print PE characteristics
    public static void PrintPeCharacteristics(ushort ch)
    {
        string[] image_file_str = {
            "IMAGE_FILE_RELOCS_STRIPPED", "IMAGE_FILE_EXECUTABLE_IMAGE",
            "IMAGE_FILE_LINE_NUMS_STRIPPED", "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
            "IMAGE_FILE_AGGRESSIVE_WS_TRIM", "IMAGE_FILE_LARGE_ADDRESS_AWARE",
            "IMAGE_FILE_BYTES_REVERSED_LO", "IMAGE_FILE_32BIT_MACHINE",
            "IMAGE_FILE_DEBUG_STRIPPED", "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
            "IMAGE_FILE_NET_RUN_FROM_SWAP", "IMAGE_FILE_SYSTEM", "IMAGE_FILE_DLL",
            "IMAGE_FILE_UP_SYSTEM_ONLY", "IMAGE_FILE_BYTES_REVERSED_HI"
        };

        ushort[] image_file_arr = {
            0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0080, 0x0100,
            0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000
        };

        for (int idx = 0; idx < 15; idx++)
        {
            if ((ch & image_file_arr[idx]) != 0)
                Console.WriteLine($"     {image_file_str[idx]}");
        }
    }

    // Function to print DLL characteristics
    public static void PrintDllCharacteristics(ushort ch)
    {
        string[] image_dll_str = {
            "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
            "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
            "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
            "IMAGE_DLLCHARACTERISTICS_NO_SEH",
            "IMAGE_DLLCHARACTERISTICS_NO_BIND",
            "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
            "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
            "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
            "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"
        };

        ushort[] image_dll_arr = {
            0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000,
            0x2000, 0x4000, 0x8000
        };

        for (int idx = 0; idx < 11; idx++)
        {
            if ((ch & image_dll_arr[idx]) != 0)
                Console.WriteLine($"     {image_dll_str[idx]}");
        }
    }

    // Function to print the type of a PE image
    public static void PrintMagic(ushort magic)
    {
        switch (magic)
        {
            case 0x10B:
                Console.WriteLine("10B (PE)");
                break;
            case 0x20B:
                Console.WriteLine("20B (PE+)");
                break;
            default:
                Console.WriteLine("0 (Error)");
                break;
        }
    }

    // Function to print the machine type of a PE image
    public static void PrintMachine(ushort mach)
    {
        switch (mach)
        {
            case 0x0000:
                Console.WriteLine("(0000)  IMAGE_FILE_MACHINE_UNKNOWN");
                break;
            case 0x0200:
                Console.WriteLine("(0200)  IMAGE_FILE_MACHINE_IA64");
                break;
            case 0x014C:
                Console.WriteLine("(014C)  IMAGE_FILE_MACHINE_I386");
                break;
            case 0x8664:
                Console.WriteLine("(8664)  IMAGE_FILE_MACHINE_AMD64");
                break;
            case 0x01C0:
                Console.WriteLine("(01C0)  IMAGE_FILE_MACHINE_ARM");
                break;
            case 0xAA64:
                Console.WriteLine("(AA64)  IMAGE_FILE_MACHINE_ARM64");
                break;
            case 0x01C4:
                Console.WriteLine("(01C4)  IMAGE_FILE_MACHINE_ARMNT");
                break;
            case 0x0EBC:
                Console.WriteLine("(0EBC)  IMAGE_FILE_MACHINE_EBC");
                break;
            default:
                break;
        }
    }

    // Function to print the subsystem of a PE
    public static void PrintSubsystem(ushort system)
    {
        switch (system)
        {
            case 0x0000:
                Console.WriteLine("  (0000)   IMAGE_SUBSYSTEM_UNKNOWN");
                break;
            case 0x0001:
                Console.WriteLine("  (0001)   IMAGE_SUBSYSTEM_NATIVE");
                break;
            case 0x0002:
                Console.WriteLine("  (0002)   IMAGE_SUBSYSTEM_WINDOWS_GUI");
                break;
            case 0x0003:
                Console.WriteLine("  (0003)   IMAGE_SUBSYSTEM_WINDOWS_CUI");
                break;
            case 0x0005:
                Console.WriteLine("     IMAGE_SUBSYSTEM_OS2_CUI");
                break;
            case 0x0007:
                Console.WriteLine("     IMAGE_SUBSYSTEM_POSIX_CUI");
                break;
            case 0x0008:
                Console.WriteLine("     IMAGE_SUBSYSTEM_NATIVE_WINDOWS");
                break;
            case 0x0009:
                Console.WriteLine("     IMAGE_SUBSYSTEM_WINDOWS_CE_GUI");
                break;
            case 0x000A:
                Console.WriteLine("     IMAGE_SUBSYSTEM_EFI_APPLICATION");
                break;
            case 0x000B:
                Console.WriteLine("     IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER");
                break;
            case 0x000C:
                Console.WriteLine("     IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER");
                break;
            case 0x000D:
                Console.WriteLine("     IMAGE_SUBSYSTEM_EFI_ROM");
                break;
            case 0x0010:
                Console.WriteLine("     IMAGE_SUBSYSTEM_XBOX");
                break;
            case 0x0014:
                Console.WriteLine("     IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION");
                break;
            default:
                break;
        }
    }

    // Function to print the flags set on a section
    public static void PrintSectionCharacteristics(uint ch)
    {
        string[] section_flags_str = {
            "IMAGE_SCN_TYPE_NO_PAD", "IMAGE_SCN_CNT_CODE", "IMAGE_SCN_CNT_INITIALIZED_DATA",
            "IMAGE_SCN_CNT_UNINITIALIZED_ DATA", "IMAGE_SCN_LNK_OTHER", "IMAGE_SCN_LNK_INFO",
            "IMAGE_SCN_LNK_REMOVE", "IMAGE_SCN_LNK_COMDAT", "IMAGE_SCN_GPREL", "IMAGE_SCN_MEM_PURGEABLE",
            "IMAGE_SCN_MEM_16BIT", "IMAGE_SCN_MEM_LOCKED", "IMAGE_SCN_MEM_PRELOAD", "IMAGE_SCN_ALIGN_1BYTES",
            "IMAGE_SCN_ALIGN_2BYTES", "IMAGE_SCN_ALIGN_4BYTES", "IMAGE_SCN_ALIGN_8BYTES", "IMAGE_SCN_ALIGN_16BYTES",
            "IMAGE_SCN_ALIGN_32BYTES", "IMAGE_SCN_ALIGN_64BYTES", "IMAGE_SCN_ALIGN_128BYTES", "IMAGE_SCN_ALIGN_256BYTES",
            "IMAGE_SCN_ALIGN_512BYTES", "IMAGE_SCN_ALIGN_1024BYTES", "IMAGE_SCN_ALIGN_2048BYTES", "IMAGE_SCN_ALIGN_4096BYTES",
            "IMAGE_SCN_ALIGN_8192BYTES", "IMAGE_SCN_LNK_NRELOC_OVFL", "IMAGE_SCN_MEM_DISCARDABLE", "IMAGE_SCN_MEM_NOT_CACHED",
            "IMAGE_SCN_MEM_NOT_PAGED", "IMAGE_SCN_MEM_SHARED", "IMAGE_SCN_MEM_EXECUTE", "IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_WRITE"
        };

        uint[] section_flags_arr = {
            0x00000008, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000800, 0x00001000,
            0x00008000, 0x00020000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00300000,
            0x00400000, 0x00500000, 0x00600000, 0x00700000, 0x00800000, 0x00900000, 0x00A00000, 0x00B00000,
            0x00C00000, 0x00D00000, 0x00E00000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
            0x20000000, 0x40000000, 0x80000000
        };

        for (int i = 0; i < 35; i++)
        {
            if ((ch & section_flags_arr[i]) != 0)
            {
                Console.WriteLine($"          {section_flags_str[i]}");
            }
        }
    }

    // Function to read DOS Header values from a file
    public static void ReadDos(BinaryReader reader, ref DosHeader dosHeader)
    {
        // Reading DOS Header
        dosHeader.magic = Read16LE(reader);
        dosHeader.e_cblp = Read16LE(reader);
        dosHeader.e_cp = Read16LE(reader);
        dosHeader.e_crlc = Read16LE(reader);
        dosHeader.e_cparhdr = Read16LE(reader);
        dosHeader.e_minalloc = Read16LE(reader);
        dosHeader.e_maxalloc = Read16LE(reader);
        dosHeader.e_ss = Read16LE(reader);
        dosHeader.e_sp = Read16LE(reader);
        dosHeader.e_csum = Read16LE(reader);
        dosHeader.e_ip = Read16LE(reader);
        dosHeader.e_cs = Read16LE(reader);
        dosHeader.e_lfarlc = Read16LE(reader);
        dosHeader.e_ovno = Read16LE(reader);

        // some of the next fields are reserved/aren't used
        dosHeader.e_res = Read64LE(reader);
        dosHeader.e_oemid = Read16LE(reader);
        dosHeader.e_oeminfo = Read16LE(reader);
        dosHeader.e_res2 = Read64LE(reader); // this is repeated on purpose since
        dosHeader.e_res2 = Read64LE(reader); // most PE files have this field as zero
        dosHeader.e_res2 = Read32LE(reader); // i'll fix it later.
        /////////////////////////////////////////////
        dosHeader.e_lfanew = Read32LE(reader);
    }

    // Function to read PE header information
    public static void ReadPe(BinaryReader reader, ref DosHeader dosHeader)
    {
        reader.BaseStream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

        // PE header
        dosHeader.pe.signature = Read32LE(reader);
        dosHeader.pe.machine = Read16LE(reader);
        dosHeader.pe.numberOfSections = Read16LE(reader);
        dosHeader.pe.timeStamp = Read32LE(reader);
        dosHeader.pe.symTablePtr = Read32LE(reader);
        dosHeader.pe.numberOfSym = Read32LE(reader);
        dosHeader.pe.optionalHeaderSize = Read16LE(reader);
        dosHeader.pe.characteristics = Read16LE(reader);

        // optional header (Standard Fields)
        dosHeader.pe.optionalHeader.magic = Read16LE(reader);
        dosHeader.pe.optionalHeader.majorLinkerVer = reader.ReadByte();
        dosHeader.pe.optionalHeader.minorLinkerVer = reader.ReadByte();
        dosHeader.pe.optionalHeader.sizeOfCode = Read32LE(reader);
        dosHeader.pe.optionalHeader.sizeOfInitializedData = Read32LE(reader);
        dosHeader.pe.optionalHeader.sizeOfUninitializedData = Read32LE(reader);
        dosHeader.pe.optionalHeader.entryPoint = Read32LE(reader);
        dosHeader.pe.optionalHeader.baseOfCode = Read32LE(reader);
        if (dosHeader.pe.optionalHeader.magic == 0x20B)
        {
            dosHeader.pe.optionalHeader.imageBase = Read64LE(reader);
        }
        else
        {
            dosHeader.pe.optionalHeader.baseOfData = Read32LE(reader);
            dosHeader.pe.optionalHeader.imageBase = Read32LE(reader);
        }

        dosHeader.pe.optionalHeader.sectionAlignment = Read32LE(reader);
        dosHeader.pe.optionalHeader.fileAlignment = Read32LE(reader);
        dosHeader.pe.optionalHeader.majorOSVer = Read16LE(reader);
        dosHeader.pe.optionalHeader.minorOSVer = Read16LE(reader);
        dosHeader.pe.optionalHeader.majorImageVer = Read16LE(reader);
        dosHeader.pe.optionalHeader.minorImageVer = Read16LE(reader);
        dosHeader.pe.optionalHeader.majorSubsystemVer = Read16LE(reader);
        dosHeader.pe.optionalHeader.minorSubsystemVer = Read16LE(reader);
        dosHeader.pe.optionalHeader.win32VersionVal = Read32LE(reader);
        dosHeader.pe.optionalHeader.sizeOfImage = Read32LE(reader);
        dosHeader.pe.optionalHeader.sizeOfHeaders = Read32LE(reader);
        dosHeader.pe.optionalHeader.checkSum = Read32LE(reader);
        dosHeader.pe.optionalHeader.subsystem = Read16LE(reader);
        dosHeader.pe.optionalHeader.dllCharacteristics = Read16LE(reader);

        if (dosHeader.pe.optionalHeader.magic == 0x20B)
        {
            dosHeader.pe.optionalHeader.sizeOfStackReserve = Read64LE(reader);
            dosHeader.pe.optionalHeader.sizeOfStackCommit = Read64LE(reader);
            dosHeader.pe.optionalHeader.sizeOfHeapReserve = Read64LE(reader);
            dosHeader.pe.optionalHeader.sizeOfHeapCommit = Read64LE(reader);
        }
        else
        {
            dosHeader.pe.optionalHeader.sizeOfStackReserve = Read32LE(reader);
            dosHeader.pe.optionalHeader.sizeOfStackCommit = Read32LE(reader);
            dosHeader.pe.optionalHeader.sizeOfHeapReserve = Read32LE(reader);
            dosHeader.pe.optionalHeader.sizeOfHeapCommit = Read32LE(reader);
        }
        dosHeader.pe.optionalHeader.loaderFlags = Read32LE(reader);
        dosHeader.pe.optionalHeader.numberOfRvaAndSizes = Read32LE(reader);
    }

    // Function to read Data Directories information
    public static void ReadDataDir(BinaryReader reader, ref DosHeader dosHeader)
    {
        uint dirs = dosHeader.pe.optionalHeader.numberOfRvaAndSizes;

        // Reading Data Directories
        dosHeader.dataDirectory = new DataDirectory[dirs];

        for (int idx = 0; idx < dirs; idx++)
        {
            dosHeader.dataDirectory[idx].virtualAddr = Read32LE(reader);
            dosHeader.dataDirectory[idx].size = Read32LE(reader);
            // dosHeader.dataDirectory[idx].offset = RvaToOffset(dosHeader.pe.numberOfSections,
            //                               dosHeader.dataDirectory[idx].virtualAddr,
            //                               dosHeader.section_table);
        }
    }

    public static void ReadDataOffset(ref DosHeader dosHeader)
    {
        uint dirs = dosHeader.pe.optionalHeader.numberOfRvaAndSizes;

        for (int idx = 0; idx < dirs; idx++)
        {
            dosHeader.dataDirectory![idx].offset = (long)RvaToOffset(dosHeader.pe.numberOfSections,
                                      dosHeader.dataDirectory![idx].virtualAddr,
                                      dosHeader.section_table!);
        }
    }

    // Function to read sections information
    public static void ReadSections(BinaryReader reader, ref DosHeader dosHeader)
    {
        int sections = dosHeader.pe.numberOfSections;
        // Reading Sections data
        dosHeader.section_table = new SectionTable[sections];

        for (int idx = 0; idx < sections; idx++)
        {
            dosHeader.section_table[idx].name = ReadStr(reader, 8);
            dosHeader.section_table[idx].virtualSize = Read32LE(reader);
            dosHeader.section_table[idx].virtualAddr = Read32LE(reader);
            dosHeader.section_table[idx].sizeOfRawData = Read32LE(reader);
            dosHeader.section_table[idx].ptrToRawData = Read32LE(reader);
            dosHeader.section_table[idx].ptrToReloc = Read32LE(reader);
            dosHeader.section_table[idx].ptrToLineNum = Read32LE(reader);
            dosHeader.section_table[idx].numberOfReloc = Read16LE(reader);
            dosHeader.section_table[idx].numberOfLineNum = Read16LE(reader);
            dosHeader.section_table[idx].characteristics = Read32LE(reader);
        }
    }

    // Function to read Export directory information
    public static void ReadExportDir(BinaryReader reader, ref DosHeader dosHeader)
    {
        uint offset;

        offset = (uint)dosHeader.dataDirectory![0].offset;

        if (offset == uint.MaxValue) return;

        reader.BaseStream.Seek(offset, SeekOrigin.Begin);

        dosHeader.exportDir.exportFlags = Read32LE(reader);
        dosHeader.exportDir.timeStamp = Read32LE(reader);
        dosHeader.exportDir.majorVer = Read16LE(reader);
        dosHeader.exportDir.minorVer = Read16LE(reader);
        dosHeader.exportDir.nameRVA = Read32LE(reader);
        dosHeader.exportDir.ordinalBase = Read32LE(reader);
        dosHeader.exportDir.addrTableEntries = Read32LE(reader);
        dosHeader.exportDir.numberOfNamePointers = Read32LE(reader);
        dosHeader.exportDir.exportAddrTableRVA = Read32LE(reader);
        dosHeader.exportDir.namePtrRVA = Read32LE(reader);
        dosHeader.exportDir.ordinalTableRVA = Read32LE(reader);

        ReadExportNames(reader, ref dosHeader);
    }

    // Function to read the ascii names of exported functions
    public static void ReadExportNames(BinaryReader reader, ref DosHeader dosHeader)
    {
        uint tableOffset;
        uint nameOffset;
        uint nameRVA;
        uint tableSize;
        char[] buffer = new char[100];

        tableSize = dosHeader.exportDir.numberOfNamePointers;
        tableOffset = (uint)RvaToOffset(dosHeader.pe.numberOfSections,
                                       dosHeader.exportDir.namePtrRVA,
                                       dosHeader.section_table!);
        dosHeader.exportDir.exportAddr_name_t = new ExportAddressName[tableSize];

        // reading Import table entries (per DLL)
        for (uint idx = 0; idx < tableSize; idx++)
        {
            reader.BaseStream.Seek(tableOffset, SeekOrigin.Begin);
            nameRVA = Read32LE(reader);
            nameOffset = (uint)RvaToOffset(dosHeader.pe.numberOfSections,
                  nameRVA, dosHeader.section_table!);
            reader.BaseStream.Seek(nameOffset, SeekOrigin.Begin);
            reader.Read(buffer, 0, 100);
            dosHeader.exportDir.exportAddr_name_t[idx].names = new string(buffer).TrimEnd('\0');

            tableOffset += 4; // after reading 4 bytes, jump to next 4 bytes
        }
    }

    // Function to read the imports table entries
    public static void ReadImportDir(BinaryReader reader, ref DosHeader dosHeader)
    {
        uint tableEntries;

        // each import entry has 5 fields, 4 bytes per field (20 bytes per entry)
        // minus 1 because the final table will be empty signaling the end of entries
        tableEntries = (dosHeader.dataDirectory![1].size / 20) - 1;
        reader.BaseStream.Seek(dosHeader.dataDirectory[1].offset, SeekOrigin.Begin);

        dosHeader.importDir = new ImportDirectory[tableEntries];

        for (uint idx = 0; idx < tableEntries; idx++)
        {
            dosHeader.importDir[idx].importLookupTableRVA = Read32LE(reader);
            dosHeader.importDir[idx].timeStamp = Read32LE(reader);
            dosHeader.importDir[idx].forwarderChain = Read32LE(reader);
            dosHeader.importDir[idx].nameRVA = Read32LE(reader);
            dosHeader.importDir[idx].importAddressRVA = Read32LE(reader);
        }
    }
}