/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* COMPATIBLE WITH Rivals of Aether II version 1.2.0 -                      */
/* 04-08-2025 - 16911 - [release]                                           */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
// Compile with:
// gcc hideElo-3.0.c -o hideElo-3.0.exe

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
	BOOL anyModules = Module32First(snapshot, &me32);
	if (!anyModules) me32.modBaseAddr = NULL;
	while (anyModules) {
		if (strcmp(ModuleName, me32.szModule) == 0) break;
		if (!Module32Next(snapshot, &me32)) {
			me32.modBaseAddr = NULL;
			break;
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
	if (nibble <= 9) return nibble;
	nibble = hex - 'a';
	if (nibble <= 5) return nibble + 10;
	nibble = hex - 'A';
	if (nibble <= 5) return nibble + 10;
	return 0xFF;
}

/**
 * Represents an array of bytes to scan memory for, where some of those bytes
 * are treated as wildcards (any byte in memory will match). If the byte in
 * .bytes is checked, the corresponding byte in .mask is 0xFF. If it's a
 * wildcard, the .mask byte is 0x00.
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
 * where wildcards are represented by ??, e.g. "7C 37 ?? 81". This is the same
 * style used by Cheat Engine, except half-byte wildcards (e.g. ?7 or 3?) are
 * not supported (because I didn't see the benefit).
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
			ret.mask[a] = 0x00;
			continue;
		}
		byte nibble1 = hexCharToInt(char1);
		byte nibble2 = hexCharToInt(char2);
		if (nibble1 == 0xFF || nibble2 == 0xFF) {
			valid = FALSE;
			break;
		}
		ret.bytes[a] = (nibble1 << 4) + nibble2;
		ret.mask[a] = 0xFF;
	}
	if (!valid) {
		ret.len = 0;
		freeAOBPattern(ret);
		ret.bytes = NULL;
		ret.mask = NULL;
	}
	return ret;
}

#define AOB_NO_MATCH -1
#define AOB_PATTERN_INVALID -2
/**
 * Searches the memory of the given process between the addresses moduleBase and
 * moduleEnd for a segment matching the given pattern (provided in IDA format,
 * except only full-byte wildcards ?? are supported), then writes the bytes in
 * patchBytes at the address of the match + patchOffset. 
 *
 * This is meant to be easy to adapt from a CheatEngine AOB Injection script.
 * Use `FindProcessId` and `OpenProcess` to get the `process` handle, and
 * `FindModule` to find the boundaries of the module based on the name you find
 * in the Cheat Engine AOB script call to `aobscanmodule()`. In the same call,
 * you'll see the AOB sequence of bytes, which can be copied into a C string
 * as-is for the `idaPattern` parameter.
 *
 * For `patchOffset`, find the number following the injection-point label (the
 * same as the first parameter of `aobscanmodule`) which you should see once
 * after [ENABLE] and once after [DISABLE], e.g. `INJECT_MyCheat+0B:` would
 * correspond to a patchOffset of 0x0B. Note that the offset is always in hex,
 * so you should use a 0x hex literal in this program. 
 *
 * For `patchBytes`, you will need to see the sequence of bytes corresponding to
 * the assembled machine code in the [ENABLE] section. You can get this either
 * by using the `Disassemble this code region` option and copying the bytes of
 * the injected code, or by using any other x86 assembler software.
 *
 * Finally, `patchLen` is the number of bytes in `patchBytes`. This does not
 * include the null terminator, only the number of bytes you want written.
 *
 * If, after searching the entire memory region, no match is found, no changes
 * are made and `AOB_NO_MATCH` is returned. If the given pattern is not valid,
 * `AOB_PATTERN_INVALID` is returned. The function will also printf a
 * corresponding message (including the `description` parameter) when it
 * returns, both for success and failure.
 *
 * !!!IMPORTANT NOTE!!!: This does NOT create jumps and code caves! It only
 * write bytes directly to the target location. Thus, you must make sure your
 * cheat is a simple byte substitution of the exact same length as the
 * instructions you are trying to overwrite. Cheat engine will create jumps and
 * code caves by default if you use the AOB Injection template, even if your new
 * code would fit within the space of the target, so you'll need to figure this
 * out manually. This will usually require some extra creativity and some NOPs,
 * but some cheats may simply not be possible with this limitation.
 */
DWORD64 aobInject(
	const char* description,
	const HANDLE process, const DWORD64 moduleBase, const DWORD64 moduleEnd,
	char* idaPattern, const DWORD64 patchOffset,
	char* patchBytes, DWORD64 patchLen
) {
	struct aobPattern aob = idaPatternToStruct(idaPattern);
	if (aob.len == 0) {
		printf(
			"ERROR: \"%s\" failed because the AOB pattern \"%s\" is invalid.\n",
			description, idaPattern
		);
		return AOB_PATTERN_INVALID;
	}

	DWORD64 matchAddr;
	size_t aobIndex = 0;
	DWORD64 scanAddr = moduleBase;
	DWORD64 lastScanAddr = moduleBase;
	
	// Memory buffer size, must be no more than 0x1000 or this will cause the
	// target process to crash (not 100% sure why...)
	#define MBSIZE 0x1000ULL
	char memBuffer[MBSIZE];
	ReadFromMemory(process, scanAddr, MBSIZE, memBuffer);
	size_t buffIndex = 0;

	// Look for a match in memory, while only looking at MBSIZE bytes at a time
	while (TRUE) {
		if (!aob.mask[aobIndex] || memBuffer[buffIndex] == aob.bytes[aobIndex]) {
			// If finding the start of a new match, save address
			if (aobIndex == 0) matchAddr = scanAddr + buffIndex;
			++aobIndex;
			if (aobIndex == aob.len) break;
		}
		else if (aobIndex != 0) {
			// Return match head to start of search string
			aobIndex = 0;
			// Return mem buffer segment to contain byte after start of previous
			// match. If MBSIZE is a power of 2, `/MBSIZE*MBSIZE` should be
			// optimized to `&-MBSIZE`.
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
			printf(
				"ERROR: \"%s\" failed because no match was found for the AOB pattern.\n",
				description
			);
			return AOB_NO_MATCH;
		}
		// Actually read memory to change which section of memory is being read:
		if (scanAddr != lastScanAddr) {
			ReadFromMemory(process, scanAddr, MBSIZE, memBuffer);
			lastScanAddr = scanAddr;
		}
	}
	freeAOBPattern(aob);
	
	DWORD64 patchAddr = matchAddr + patchOffset;
	WriteIntoMemory(process, patchAddr, patchLen, patchBytes);
	printf(
		"\"%s\" patch applied at address 0x%08llX (offset 0x%08llX).\n",
		description, patchAddr, patchAddr-moduleBase
	);
	return patchAddr;
}

#define TARGET_PROCESS_NAME "Rivals2-Win64-Shipping.exe"
#define MODULE_NAME "Rivals2-Win64-Shipping.exe"
int main(int argc, char **argv) {
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
	
	// Your Ranked rank (Stone, Bronze, Silver, Gold, PLatinum, Diamond, Master,
	// Grandmaster, or Aetherian) is represented by a number from 1 to 9, where
	// 1 is Stone and 9 is Aetherian. Here, we manually set the rank to 9 at a
	// point where it won't affect matchmaking, but does affect every ranked
	// icon visible in-game. If you rename the executable to end in 'r' followed
	// by a number between 1 and 8 (e.g. "hideElo-3.0r1.exe") it will use the
	// corresponding rank icon instead of Aetherian.
	char* exeName = argv[0];
    int exeNameLen = strlen(exeName);
    char lastChar = exeName[exeNameLen-5];
    char rank = 9;
    if (exeName[exeNameLen-6] == 'r' && lastChar >= '1' && lastChar <= '8') {
        rank = lastChar - '0';
    }
	char rankedTierCode[] = /* mov bx, 0009 */ "\x66\xBB\x09\x00";
	rankedTierCode[2] = rank;
	aobInject(
		"Set Ranked tier icon",
		process, modBase, modEnd,
		"41 0F B6 ?? 48 8B ?? E8 ?? ?? ?? ?? 48 8B ?? 48 83 ?? ?? ?? ?? ?? ?? 75 08 48 8B ?? E8 ?? ?? ?? ?? 4C 8B ?? ?? ?? ?? ?? 48 89", 0x0,
		rankedTierCode, 4
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
		"41 ?? ?? 48 89 ?? 24 ?? 48 89 ?? 24 ?? E8 ?? ?? ?? ?? 48 8D ?? 24 ??", +0xd,
		/* nop (5 bytes) */"\x0F\x1F\x44\x00\x01", 5
	);

	// This hides your previous and new Elo displayed after a ranked set.
	aobInject(
		"Hide post-set Elo display",
		process, modBase, modEnd,
		"80 ?? ?? 00 74 ?? 41 8B ?? 48 8B ?? E8 ?? ?? ?? ?? 48 8B", +0x20,
		/* nop (5 bytes) */"\x0F\x1F\x44\x00\x01", 5
	);

	// This is my best attempt at hiding the "-Win Streak" text you see online.
	// I wasn't able to prevent it from displaying entirely, or make it always
	// show a specific number, but I found a way to set the length of the string
	// to a high value (255 characters in this case). The game then tries to
	// shrink the very long string to into the same space, making it very
	// difficult to read. This means you can tell if someone has a win streak of
	// at least one, since you'll see a fuzzy line on their side of the screen,
	// but you won't be able to easily tell how big their streak is. Don't ask
	// for a better solution because I spent multiple working days on this
	// already! This works by hooking into a function which runs once for pretty
	// much every string in-game and on the character-select screen. It checks
	// for a string which begins with "-W" (in UTF-16) and a length of 12 (0xC)
	// and sets its length to 0xFF (255). This could theoretically match a
	// Player Tag, but it's unlikely. This injection does overwrite some checks
	// which appear to be for empty/null strings, but it doesn't seem to cause
	// any crashes (I hope...).
	aobInject(
		"Obfuscate Win Streaks",
		process, modBase, modEnd,
		"48 85 ?? 0F 84 ?? ?? 00 00 EB 0A 4C 8D", +0x0,
		/* cmp [rbx],0057002D */     "\x81\x3B\x2D\x00\x57\x00"\
		/* jne rip+C */              "\x75\x0A"\
		/* cmp byte ptr [rcx+08],0C*/"\x80\x79\x08\x0C"\
		/* jne rip+6*/               "\x75\x04"\
		/* mov byte ptr [rax+08],FF*/"\xC6\x41\x08\xFF", 18
	);
	CloseHandle(process);
}