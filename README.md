TLSInfect
=========

Windows 32-bit executable infector

Summary
	- Infects 32 bit executable files
	- Appends desired x86 shellcode to a new tls callback
	- Preserves original entry point of the file
	
Limitations
	- All tls callbacks get called both on startup and exit, so the code will be executed twice
	- Does not infect files with a tls section already
	- Files need DEP disabled (will disable in the NT Header next update)
	- Probably some things i'm forgetting
	
