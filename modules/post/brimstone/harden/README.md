post/brimstone/harden
---------------------

This is a set of metasploit post modules to harden linux and windows systems.

1. Check this out into the metasploit framework as `modules/post/brimstone/harden`
2. Launch an exploit/multi/handler with a meterpreter payload and AutoRunScript set to post/brimstone/harden. See msfconsole.rc for an example.
3. Use msfvenom and build an executable payload to match.
4. Transfer and detonate the payload on the target system.