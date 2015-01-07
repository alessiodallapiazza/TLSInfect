TLSInfect
=========

Infects 32-bit portable executabels through TLS

# Summary:
	• Infects 32 bit executable files
	• Appends desired x86 shellcode to a new tls callback
	• Preserves original entry point of the file

# Limitations:
	• All tls callbacks get called both on startup and exit, so the code will be executed twice
	• Does not infect files with a tls section already
	• One library needs to import kernel32.dll (for any TLS)
	• Does not handle overlay/eof data (could be some digital signatures)
	• Needs DEP disabled, (IMAGE_DLLCHARACTERISTICS_NX_COMPAT), or I guess the section could just be assigned executable characteristics, but that would be heuristically incorrect.
