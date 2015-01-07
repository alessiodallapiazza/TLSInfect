#include <stdio.h>
#include <Windows.h>

#define ALIGN_UP(x,y) ((x+(y-1))&(~(y-1)))

unsigned char Code[] =
{
	0xCC
};

void main(void)
{
	char szFilePath[MAX_PATH];

	printf("file path:");
	scanf("%s", &szFilePath);

	HANDLE hFile = CreateFileA(szFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	DWORD dwFileSize = GetFileSize(hFile, 0);

	// assumes section_alignment of 0x1000 
	dwFileSize += ALIGN_UP(sizeof(Code)+sizeof(IMAGE_TLS_DIRECTORY)+12, 0x1000);

	HANDLE hFileMapping = CreateFileMappingA(hFile, 0, PAGE_READWRITE, 0, dwFileSize, 0);
	if (hFileMapping == INVALID_HANDLE_VALUE)
		return;

	LPVOID pExe = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pExe;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)pExe + pIDH->e_lfanew);

	// 32 bit
	if (pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		return;

	// DEP enabled 
	if (pINH->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		return;

	// already has tls
	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		return;

	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
	PIMAGE_SECTION_HEADER pLastSection = pISH;

	// find last section
	for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		if (pLastSection->PointerToRawData < pISH->PointerToRawData &&
			pLastSection->VirtualAddress < pISH->VirtualAddress)
		{
			pLastSection = pISH;
		}
		pISH++;
	}

	// increase field cuz we're adding a section
	pINH->FileHeader.NumberOfSections++;

	// properly alignt the last section so we can add another
	pLastSection->SizeOfRawData = ALIGN_UP(pLastSection->SizeOfRawData, pINH->OptionalHeader.FileAlignment);
	pLastSection->Misc.VirtualSize = ALIGN_UP(pLastSection->Misc.VirtualSize, pINH->OptionalHeader.SectionAlignment);

	PIMAGE_SECTION_HEADER pTLSSection = pLastSection;
	pTLSSection++; // increment to our added section

	lstrcpyA((CHAR*)pTLSSection->Name, ".tls"); // name
	pTLSSection->SizeOfRawData = ALIGN_UP(sizeof(Code)+sizeof(IMAGE_TLS_DIRECTORY)+12, pINH->OptionalHeader.FileAlignment);
	pTLSSection->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	pTLSSection->Misc.VirtualSize = sizeof(Code)+sizeof(IMAGE_TLS_DIRECTORY)+12;
	pTLSSection->VirtualAddress = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;

	pTLSSection->PointerToRelocations = 0;
	pTLSSection->PointerToLinenumbers = 0;
	pTLSSection->NumberOfRelocations = 0;
	pTLSSection->NumberOfLinenumbers = 0;

	pTLSSection->Characteristics = 0xC0000040;

	// struct: (base of section)
	// index
	// address_of_index
	// address_of_callback
	// tls_directory
	// tls_code

	// Move to the end of the last section
	DWORD dwWrite = (DWORD)pExe + pTLSSection->PointerToRawData;

	// empty DWORD (index)
	char index[4] = { 0x00, 0x00, 0x00, 0x00 };

	// write index value (NULL)
	memcpy((PVOID)dwWrite, index, sizeof(index));
	dwWrite += 4;

	// calculate offset of index (useless)
	DWORD dwOffsetOfIndexDWORD = pINH->OptionalHeader.ImageBase + pTLSSection->VirtualAddress;

	// write offset
	memcpy((PVOID)dwWrite, &dwOffsetOfIndexDWORD, sizeof(DWORD));
	dwWrite += 4;

	// calculate offset of writing code
	DWORD dwOffsetOfCodeDWORD = pINH->OptionalHeader.ImageBase + pTLSSection->VirtualAddress + 12 + sizeof(IMAGE_TLS_DIRECTORY);

	// write offset
	memcpy((PVOID)dwWrite, &dwOffsetOfCodeDWORD, sizeof(DWORD));
	dwWrite += 4;

	// init tls directory
	IMAGE_TLS_DIRECTORY* pTLS = new IMAGE_TLS_DIRECTORY();
	pTLS->AddressOfIndex = pINH->OptionalHeader.ImageBase + pTLSSection->VirtualAddress + 4;
	pTLS->AddressOfCallBacks = pINH->OptionalHeader.ImageBase + pTLSSection->VirtualAddress + 8;

	// write tls directory
	memcpy((PVOID)dwWrite, (PVOID)pTLS, sizeof(IMAGE_TLS_DIRECTORY));
	dwWrite += sizeof(IMAGE_TLS_DIRECTORY);

	// write callback code
	memcpy((PVOID)dwWrite, Code, sizeof(Code));
	dwWrite += sizeof(Code);

	// add tls entry to data directory
	pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY);
	pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = pTLSSection->VirtualAddress + 12;

	// recalc file size
	pINH->OptionalHeader.SizeOfImage = pTLSSection->VirtualAddress + ALIGN_UP(pTLSSection->Misc.VirtualSize, pINH->OptionalHeader.SectionAlignment);

	UnmapViewOfFile(pExe);
}