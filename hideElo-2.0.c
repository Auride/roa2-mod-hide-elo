/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* COMPATIBLE WITH Rivals of Aether II version 11-28-2024-12750 - [release] */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
// Compile with:
// gcc hideElo-2.0.c -o hideElo-2.0.exe

// If you don't have the gcc C compiler, you can get it from
// https://winlibs.com/

// To see/edit the actual cheat data, go to the "main" function at the bottom,
// particularly the calls to "aobInject".

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#define ALIGN_PAGE_DOWN(VALUE) (((DWORD64)VALUE) & ~((0x1000ULL) - 1))
#define ALIGN_PAGE_UP(VALUE) ((((DWORD64)VALUE) + ((0x1000ULL) - 1)) & ~((0x1000ULL) - 1))

DWORD FindProcessId(LPCSTR ProcessName)
{
	DWORD processId = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &pe32))
	{
		do
		{
			if (strcmp(ProcessName, pe32.szExeFile) == 0)
			{
				processId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &pe32));
	}

	CloseHandle(snapshot);

	return processId;
}

/**
 * Returns the MODULEENTRY32 for the module under the given process with the
 * given name. If no matching module is found, .modBaseAddr will be NULL.
 */
MODULEENTRY32 FindModule(DWORD ProcessId, LPCSTR ModuleName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(snapshot, &me32)) me32.modBaseAddr = NULL;
	else {
		while (TRUE) {
			if (strcmp(ModuleName, me32.szModule) == 0) break;
			if (!Module32Next(snapshot, &me32)) {
				me32.modBaseAddr = NULL;
				break;
			}
		}
	}
	CloseHandle(snapshot);
	return me32;
}

VOID ReadFromMemory(HANDLE Process, DWORD64 Base, DWORD64 Size, PVOID Buffer)
{
	DWORD64 pageBase = ALIGN_PAGE_DOWN(Base);
	DWORD64 pageSize = ALIGN_PAGE_UP(Size);

	DWORD oldProtect = 0;

	if (VirtualProtectEx(Process, (PVOID)pageBase, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		ReadProcessMemory(Process, (PVOID)Base, Buffer, Size, NULL);
		VirtualProtectEx(Process, (PVOID)pageBase, pageSize, oldProtect, &oldProtect);
	}
}

VOID WriteIntoMemory(HANDLE Process, DWORD64 Base, DWORD64 Size, PVOID Buffer)
{
	DWORD64 pageBase = ALIGN_PAGE_DOWN(Base);
	DWORD64 pageSize = ALIGN_PAGE_UP(Size);

	DWORD oldProtect = 0;

	if (VirtualProtectEx(Process, (PVOID)pageBase, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		WriteProcessMemory(Process, (PVOID)Base, Buffer, Size, NULL);
		VirtualProtectEx(Process, (PVOID)pageBase, pageSize, oldProtect, &oldProtect);
	}
}

/**
 * Returns the integer represented by a single hex character '0'-'9', 'a'-'f',
 * or 'A'-'F'. Return value is usually 0-15 (inclusive). If the parameter
 * character is not in those ranges, 0xFF (255) is returned.
 */
byte hexCharToInt(char hex) {
	byte nibble = hex - '0';
	if (nibble > 9) {
		nibble = hex - 'a';
		if (nibble > 5) {
			nibble = hex - 'A';
			if (nibble > 5) return 0xFF;
		}
		nibble += 10;
	}
	return nibble;
}

/**
 * Represents an array of bytes to scan memory for, where some of those bytes
 * are treated as wildcards (any byte in memory will match). If the byte in
 * .bytes is checked, the corresponding byte in .mask is TRUE. If it's a
 * wildcard, the .mask byte is FALSE.
 */
struct aobPattern {
	size_t len;
	char* bytes;
	char* mask;
};

/**
 * Frees the .bytes and .mask arrays within an aobPattern. Does not free the
 * aobPattern itself.
 */
void freeAOBPattern(struct aobPattern a) {
	free(a.bytes);
	free(a.mask);
}

/**
 * Takes in an IDA-style AOB pattern and returns an equivalent aobPattern
 * struct. IDA style comes from the IDA disassembler, where an array-of-bytes
 * pattern can be represented by a string of hex bytes separated by spaces,
 * where wildcards are represented by ??, e.g. "7C 37 ?? 81".This is the same
 * style used by Cheat Engine.
 *
 * If the input is not a valid pattern, the returned aobPattern will have a .len
 * of 0, and .bytes and .mask will be NULL.
 */
struct aobPattern idaPatternToStruct(char* idaPattern) {
	const size_t aobPatternLen = strlen(idaPattern);
	const size_t aobLen = (aobPatternLen + 1) / 3;
	if (aobPatternLen != aobLen * 3 - 1) {
		return (struct aobPattern) {0, NULL, NULL};
	}

	struct aobPattern ret;
	ret.len = (aobPatternLen + 1) / 3;
	ret.bytes = malloc(ret.len);
	ret.mask = malloc(ret.len);
	
	BOOL valid = TRUE;
	for (size_t a = 0, p = 0; a < aobLen; a += 1, p += 3) {
		char sep = idaPattern[p + 2];
		if (sep != ' ' && sep != '\0') {
			valid = FALSE;
			break;
		}
		char char1 = idaPattern[p];
		char char2 = idaPattern[p + 1];
		
		if (char1 == '?' && char2 == '?') {
			ret.bytes[a] = '\x00';
			ret.mask[a] = FALSE;
			continue;
		}
		byte nibble1 = hexCharToInt(char1);
		byte nibble2 = hexCharToInt(char2);
		if (nibble1 == 0xFF || nibble2 == 0xFF) {
			valid = FALSE;
			break;
		}
		ret.bytes[a] = (nibble1 << 4) + nibble2;
		ret.mask[a] = TRUE;
	}
	if (!valid) {
		ret.len = 0;
		freeAOBPattern(ret);
		ret.bytes = NULL;
		ret.mask = NULL;
	}
	return ret;
}

/**
 * 
 */
#define AOB_NO_MATCH -1
#define AOB_PATTERN_INVALID -2
DWORD64 aobInject(
	const char* description,
	const HANDLE process, const DWORD64 moduleBase, const DWORD64 moduleEnd,
	char* idaPattern, const DWORD64 patchOffset,
	byte* patchBytes
) {
	struct aobPattern aob = idaPatternToStruct(idaPattern);
	if (aob.bytes == NULL) {
		printf("ERROR: \"%s\" failed because the AOB pattern \"%s\" is invalid.\n", description, idaPattern);
		return AOB_PATTERN_INVALID;
	}

	DWORD64 matchAddr;
	size_t aobIndex = 0;
	DWORD64 scanAddr = moduleBase;
	DWORD64 lastScanAddr = 0;
	
	// Memory buffer size, must be no more than 0x1000 or this will cause the
	// target process to crash (not 100% sure why...)
	#define MBSIZE 0x1000
	char memBuffer[MBSIZE];
	ReadFromMemory(process, scanAddr, MBSIZE, memBuffer);
	size_t buffIndex = 0;

	// Look for a match in memory, while only looking at MBSIZE bytes at a time
	while (TRUE) {
		if (!aob.mask[aobIndex] || memBuffer[buffIndex] == aob.bytes[aobIndex]) {
			// If finding the start of a new match, save address
			if (aobIndex == 0) {
				matchAddr = scanAddr + buffIndex;
			}
			++aobIndex;
			if (aobIndex == aob.len) break;
		}
		else if (aobIndex != 0) {
			// Return match head to start of search string
			aobIndex = 0;
			// Return mem buffer segment to contain byte after start of previous
			// match. If MBSIZE is a power of 2, this will be optimized to an
			// AND instruction.
			scanAddr = (matchAddr+1)/MBSIZE*MBSIZE; 
			// Return mem buffer head to 1 byte after start of previous match (1
			// will be added by next line)
			buffIndex = matchAddr - scanAddr;
		}
		++buffIndex;
		// If we reached the end of the current buffer, move to the next one:
		if (buffIndex >= MBSIZE) {
			scanAddr += MBSIZE;
			buffIndex = 0;
		}
		// If we reached the end of the module memory without finding a full
		// match, break with an error value for the match address:
		if (scanAddr + buffIndex >= moduleEnd) {
			freeAOBPattern(aob);
			printf("ERROR: \"%s\" failed because no match was found for the AOB pattern.\n", description);
			return AOB_NO_MATCH;
		}
		// Actually read memory to change which section of memory is being read:
		if (scanAddr != lastScanAddr) {
			ReadFromMemory(process, scanAddr, MBSIZE, memBuffer);
			lastScanAddr = scanAddr;
		}
	}
	freeAOBPattern(aob);
	DWORD64 patchLen = strlen(patchBytes);
	
	DWORD64 patchAddr = matchAddr + patchOffset;
	WriteIntoMemory(process, matchAddr + patchOffset, patchLen, patchBytes);
	printf("\"%s\" patch applied at offset 0x%08X.\n", description, patchAddr);
	return matchAddr;
}

#define TARGET_PROCESS_NAME "Rivals2-Win64-Shipping.exe"
#define MODULE_NAME "Rivals2-Win64-Shipping.exe"
int main() {
	DWORD processId = FindProcessId(TARGET_PROCESS_NAME);
	if (processId == 0) {
		printf(
			"Process \"%s\" is not running. No changes were made.",
			TARGET_PROCESS_NAME
		);
		return 0;
	}
	MODULEENTRY32 moduleData = FindModule(processId, MODULE_NAME);
	const DWORD64 modBase = (DWORD64) moduleData.modBaseAddr;
	if (modBase == (DWORD64) NULL) {
		printf(
			"Module \"%s\" could not be found in process \"%s\". No changes were made.",
			MODULE_NAME, TARGET_PROCESS_NAME
		);
		return 0;
	}
	const DWORD64 modEnd = modBase + moduleData.modBaseSize;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// In order to guarantee that the master Elo tier icon is always shown
	// (normally requires >=1500 Elo), we can just overwrite the place where the
	// game reads your actual Elo with an immediate constant of decimal 9999.
	// The check for the icon displayed when you press the "RANKED" button from
	// the "ONLINE" menu is, for some reason, separate from the other checks.
	// The function being edited normally returns a number between 1 and 7
	// (inclusive) to determine the rank tier icon shown, where 1 is stone and 7
	// is master. If 0 is returned, then the icons come up blank/missing/empty.
	// The function normally has 7 branches where it compares against an array
	// of tier cutoffs (500, 700, 900, 1100, 1300, and >=1500 for master) but by
	// nopping out the first comparison and changing the first return to 0, we
	// can force this outcome! By overwriting this function rather than just
	// setting the Elo in memory directly, we guarantee it will always work and
	// avoid any chance of accidentally sending the wrong Elo to the servers.
	aobInject(
		"Force Ranked search tier icon to be Master",
		process, modBase, modEnd,
		"7C 37 8B 81 98 00 00 00 3B 41 60 7D 03 B0 01 C3", +0x0B,
		/* nop (2 bytes) */"\x66\x90"\
		/* mov al 07 */    "\xB0\x07"
	);

	// This works just like the above patch, but applies to a different check
	// which is used basically everywhere else in the game, as far as I can
	// tell. The only icon this doesn't affect is the one in the Ranked
	// queue/search menu.
	aobInject(
		"Force all other Ranked tier icons to be Master",
		process, modBase, modEnd,
		"7C 31 3B 51 60 7D 03 B0 01 C3", +0x05,
		/* nop (2 bytes) */"\x66\x90"\
		/* mov al 07 */    "\xB0\x07"
	);

	// This hides most instances of Elo being displayed. Instead, it's like an
	// empty string is there instead. I think this skips calling the procedure
	// which would actually render the string to begin with, but I'm not 100%
	// sure. This works in the main menu, when selecting the Ranked queue, and
	// during online matches, but does not hide your previous and new Elo
	// displayed after a ranked set.
	aobInject(
		"Hide all Elo numbers other than post-set change values",
		process, modBase, modEnd,
		"80 B9 88 00 00 00 00 48 8B FA", +0x26,
		/* nop (5 bytes) */"\x0F\x1F\x44\x00\x01"
	);

	// This hides your previous and new Elo displayed after a ranked se
	aobInject(
		"Hide post-set Elo display",
		process, modBase, modEnd,
		"80 7B 50 00 74 0B 41 8B D7 48 8B CE ?? ?? ?? ?? ?? 48 8B 07", +0x20,
		/* nop (5 bytes) */"\x0F\x1F\x44\x00\x01"
	);

	CloseHandle(process);
}