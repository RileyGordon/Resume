#include <iostream>
#include <string>
#include <fstream>
#include <Windows.h>
#include <winnt.h>
#include <vector>
using namespace std;

const int i = 1;
#define is_bigendian() ((*(char*)&i) == 0)
typedef struct {
	CHAR magic[4];
	DWORD dwModuleFlags;
	DWORD dwPeOffset;
	DWORD dwReserved;
	DWORD dwSecurityInfo;
	DWORD dwOptionalHeaderCount;
	CHAR __0x001C[0x1C];
	DWORD dwBaseAddress;
} IMAGE_XEX_HEADER, *PIMAGE_XEX_HEADER;

int g_Endian(int g_Data){
	unsigned char bTemp[4];
	if (is_bigendian())
		return i;
	bTemp[0] = (g_Data >> 0) & 255;
	bTemp[1] = (g_Data >> 8) & 0xFF;
	bTemp[2] = (g_Data >> 16) & 0xFF;
	bTemp[3] = (g_Data >> 24) & 0xFF;
	return ((int)bTemp[0] << 24) + ((int)bTemp[1] << 16) + ((int)bTemp[2] << 8) + bTemp[3];
}

int main() {
	DWORD dwStartAddress;
	DWORD dwEndAddress;
	string szImageName = "";
	BYTE bKey;

	printf("Input Image Filename: ");
	cin >> szImageName;

	printf("Input Image Encryption Key: "); //example: 0x4C or 0x2B
	cin >> bKey;

  string szBuffer = "xextool.exe -e u -c u ";
	szBuffer.append(szImageName);
	system(szBuffer.c_str());

	ifstream g_File(szImageName, ios::binary | ios::ate);
	streamsize g_Size = g_File.tellg();
	g_File.seekg(0, ios::beg);
	vector<char>g_Buffer((UINT32)g_Size);

	if (g_File.read(g_Buffer.data(), g_Size)) {
		PIMAGE_XEX_HEADER pXexHeader = (IMAGE_XEX_HEADER*)&g_Buffer[0];
		PIMAGE_DOS_HEADER pDosHeader = (IMAGE_DOS_HEADER*)&g_Buffer[g_Endian(pXexHeader->dwPeOffset)];
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(&g_Buffer[g_Endian(pXexHeader->dwPeOffset)] + pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

		printf("\n----- Image Info -----\n");
		printf("Magic: %s\n", pXexHeader->magic);
		printf("Base Address: 0x%X\n", g_Endian(pXexHeader->dwBaseAddress));
		printf("Entry Point: 0x%X\n", g_Endian(pXexHeader->dwBaseAddress) + pNtHeader->OptionalHeader.AddressOfEntryPoint);
		printf("Module Flags: 0x%X\n", g_Endian(pXexHeader->dwModuleFlags));
		printf("PE Header: 0x%X\n", g_Endian(pXexHeader->dwBaseAddress) + g_Endian(pXexHeader->dwPeOffset));
		printf("Reserved: 0x%X\n", g_Endian(pXexHeader->dwReserved));
		printf("Security Info: 0x%X\n", g_Endian(pXexHeader->dwSecurityInfo));
		printf("Optional Header Count: 0x%X\n", g_Endian(pXexHeader->dwOptionalHeaderCount));

		printf("\n----- Segment Info -----\n");
		printf("Found %d Data Segments\n", pNtHeader->FileHeader.NumberOfSections);
		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
			printf("Section %s: [0x%X - 0x%X]\n", pSectionHeader[i].Name, g_Endian(pXexHeader->dwBaseAddress) + pSectionHeader[i].VirtualAddress, g_Endian(pXexHeader->dwBaseAddress) + (pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize));
		}

		printf("\n----- Code Obfuscation -----\n");
		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
			if (!strcmp((PCHAR)pSectionHeader[i].Name, ".text")) { //start
				printf("Found '.text' Segment, Obfuscating...\n");
				DWORD dwStart = pSectionHeader[i].VirtualAddress + 0x1000;
				DWORD dwEnd = (dwStart + pSectionHeader[i].Misc.VirtualSize) - pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size;
				dwStartAddress = g_Endian(pXexHeader->dwBaseAddress) + pSectionHeader[i].VirtualAddress;
				dwEndAddress = (g_Endian(pXexHeader->dwBaseAddress) + (pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize)) - pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size;
				
  ///////////////////////////////////Encryption///////////////////////////////////////////////   
				for (int j = dwStart; j < dwEnd; j += 4){
					DWORD dwInstructionCache = DWORD((BYTE)g_Buffer.at(j + 0) << 24 | (BYTE)g_Buffer.at(j + 1) << 16 | (BYTE)g_Buffer.at(j + 2) << 8 | (BYTE)g_Buffer.at(j + 3));
					g_Buffer.at(j + 0) = (BYTE)((dwInstructionCache & 0x000000ff) >> 0);
					g_Buffer.at(j + 1) = (BYTE)((dwInstructionCache & 0x0000ff00) >> 8);
					g_Buffer.at(j + 2) = (BYTE)((dwInstructionCache & 0x00ff0000) >> 16);
					g_Buffer.at(j + 3) = (BYTE)((dwInstructionCache & 0xff000000) >> 24);
				}
				for (DWORD j = dwStart; j < dwEnd; j++){
					g_Buffer.at(j) = g_Buffer.at(j) ^ bKey;
				}
  ////////////////////////////////////////////////////////////////////////////////////////////               
				printf("Obfuscation Success!\n");
				break;
			}
		}

		printf("\n----- Save Metadata -----\n");
		DWORD dwMetaData = 0;
		unsigned char bMetaData[9] = { 'O', 'B', 'F', 'U', 'S', 'C', 'A', 'T', 'E' };
		while (memcmp(&g_Buffer[dwMetaData], (PVOID)bMetaData, 9))
			dwMetaData += 4;
		printf("Found Metadata, Saving...\n");
		g_Buffer.at(dwMetaData + 0) = BYTE(((~dwStartAddress ^ 0xA4AC24CE) & 0xff000000) >> 24);
		g_Buffer.at(dwMetaData + 1) = BYTE(((~dwStartAddress ^ 0xA4AC24CE) & 0x00ff0000) >> 16);
		g_Buffer.at(dwMetaData + 2) = BYTE(((~dwStartAddress ^ 0xA4AC24CE) & 0x0000ff00) >> 8);
		g_Buffer.at(dwMetaData + 3) = BYTE(((~dwStartAddress ^ 0xA4AC24CE) & 0x000000ff) >> 0);
		g_Buffer.at(dwMetaData + 4) = BYTE(((~dwEndAddress ^ 0xA4AC24CE) & 0xff000000) >> 24);
		g_Buffer.at(dwMetaData + 5) = BYTE(((~dwEndAddress ^ 0xA4AC24CE) & 0x00ff0000) >> 16);
		g_Buffer.at(dwMetaData + 6) = BYTE(((~dwEndAddress ^ 0xA4AC24CE) & 0x0000ff00) >> 8);
		g_Buffer.at(dwMetaData + 7) = BYTE(((~dwEndAddress ^ 0xA4AC24CE) & 0x000000ff) >> 0);
		g_Buffer.at(dwMetaData + 8) = ~bKey ^ 0xD3;
		printf("Metadata Success!\n");

		printf("\n----- Output -----\n");
		printf("Saving File \"%s%s\"...\n", "secure_", string(szImageName).c_str());
		ofstream osOutput("secure_" + string(szImageName), ofstream::binary);
		osOutput.write(&g_Buffer[0], g_Size);
		osOutput.close();
		printf("Output Success!\n");
	}
  string szBuffer = "xextool.exe -e e -c c ";
	szBuffer.append("secure_" + szImageName);
	system(szBuffer.c_str());
  
	system("pause");
	return 0;
}
