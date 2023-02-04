# ETW patches (from userMode) learned till now

### Link:
1. https://institute.sektor7.net/rto-win-evasion
2. ***`ntdll!NtTraceEvent`*** (Syscall) : https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/
3. ***`ntdll!EtwEventTrace`*** : https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/
4. https://pre.empt.dev/posts/maelstrom-etw-amsi/#Event_Tracing_for_Windows

### Main Concept:
1. Pasting _ret opcode (c3 for x64)_ at the beginning of ***`ntdll!EtwEventWrite`*** function in order to skip the Security Check done by `ntdll!__security_check_cookie`.

Video link: https://drive.google.com/file/d/1XXlBqH6aF5ZRQM9MCz83NpGfCwtMvQFe/view?usp=sharing

2. Pasting _ret opcode (c3 for x64)_ at the beginning of ***`ntdll!NtTraceEvent`*** syscall (NOT touching ETW) in order to skip `syscall` from going into kernel, so loses the capability to write ETW events to the file system..

Video link: https://drive.google.com/file/d/1LikUb86L66A0PgZqIUi97nvn-T_et2CR/view?usp=sharing

