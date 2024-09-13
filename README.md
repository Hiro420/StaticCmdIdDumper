# StaticCmdIdDumper
 A very minimal CmdId dumper for a certain anime game

# Usage
 Compile, feed it YuanShen.exe and list of get_cmdid() rvas\
 the rva list should look like this:
 ```
    KOOKJNLBAMH 0x0CCA3780
    MGDFLHGODLH 0x0BE5AA60
    CGKBCOJMLPC 0x082AB170
    OOMIIJFHPFN 0x0D16A280
    HPKKKKJDJGA 0x0A0B9800
    NOJCECKFMLL 0x0B415940
    DMHCJHMPGCJ 0x0BA55F20
    FCNMMNALFAH 0x0B8DAFB0
 ```

# Q/A
### Where do I get the RVA list?
- Dump it yourself in runtime. I'm sure [KumaDayo's Runtime Dumper](https://github.com/kuma-dayo/RuntimeDumper) should work just fine
### What's the point of this program when you can easily retrieve them in runtime/ida?
- I didn't focus on good or useful code, just made it as challenge for myself to not use any external libraries
### Why?
- Becase I could. And it was fun 
