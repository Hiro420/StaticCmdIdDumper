using System;
using System.Text;

namespace PE_Parser;

// VERY minimal
class Disassembler
{
    // Idk what I did here, but i dont like it, TODO: rewrite
    public static int Disassemble(byte[] code)
    {
        int ip = 0; // Instruction pointer

        while (ip < code.Length)
        {
            byte opcode = code[ip];

            switch (opcode)
            {
                case 0x66:
                    {
                        if (ip + 1 < code.Length && code[ip + 1] == 0xB8)
                        {
                            if (ip + 3 < code.Length)
                            {
                                ushort imm16 = BitConverter.ToUInt16(code, ip + 2);
                                // Console.WriteLine($"mov ax, 0x{imm16:X4}");
                                return imm16;
                            }
                            else
                            {
                                Console.WriteLine("Incomplete mov ax, imm16");
                                ip += 2;
                                break;
                            }
                        }
                        else
                        {
                            Console.WriteLine("Unknown instruction with operand-size override prefix");
                            ip += 1;
                            break;
                        }
                    }
                default:
                    {
                        Console.WriteLine($"Unknown instruction {opcode:X2}");
                        break;
                    }
            }
        }
        return 0;
    }
}
