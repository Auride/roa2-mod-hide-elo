// Compile with:
// gcc hideElo-1.0.c -o hideElo-1.0.exe

// If you don't have the gcc C compiler, you can get it from
// https://winlibs.com/

// To see/edit the actual cheat data, go to the "main" function at the bottom,
// particularly the calls to "TogglePatch".

#include <stdio.h>
#include <string.h>
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

DWORD64 FindModuleBase(DWORD ProcessId, LPCSTR ModuleName)
{
	DWORD64 base = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(snapshot, &me32))
	{
		do
		{
			if (strcmp(ModuleName, me32.szModule) == 0)
			{
				base = (DWORD64)me32.modBaseAddr;
				break;
			}
		} while (Module32Next(snapshot, &me32));
	}

	CloseHandle(snapshot);

	return base;
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

boolean TogglePatch(
	const char* description,
	const HANDLE process, const DWORD64 moduleBase,
	const DWORD64 patchLoc, const size_t patchLen,
	byte* origBytes, byte* patchBytes
) {
	DWORD64 targetLoc = moduleBase + patchLoc;

	byte* currBytes = malloc(patchLen);
	// Check if patch is already applied:
	ReadFromMemory(process, targetLoc, patchLen, currBytes);
	boolean isPatchAlreadyApplied = TRUE;
	for (size_t i = 0; i < patchLen; ++i) {
		if (patchBytes[i] != currBytes[i]) {
			isPatchAlreadyApplied = FALSE;
			break;
		}
	}

	if (isPatchAlreadyApplied) {
		WriteIntoMemory(process,targetLoc, patchLen, origBytes);
		printf("\"%s\" patch reverted to original game bytes.\n", description);
	} else {
		WriteIntoMemory(process,targetLoc, patchLen, patchBytes);
		printf("\"%s\" patch applied.\n", description);
	}
	free(currBytes);
	return !isPatchAlreadyApplied;
}

#define TARGET_PROCESS_NAME "Rivals2-Win64-Shipping.exe"
#define MODULE_NAME "Rivals2-Win64-Shipping.exe"
int main(){
	// Find memory location where patch will be applied/reverted:
	DWORD processId = FindProcessId(TARGET_PROCESS_NAME);
	if (processId == 0) {
		printf(
			"Process \"%s\" is not running. No changes were made.",
			TARGET_PROCESS_NAME
		);
		return 0;
	}

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	DWORD64 moduleBase = FindModuleBase(
		processId, "Rivals2-Win64-Shipping.exe"
	);

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
	TogglePatch(
		"Force Ranked search tier icon to be Master",
		process, moduleBase, 0x4E187ED, 4,
		// Original:
		/* jnl Rivals2-Win64-Shipping.exe+4E187F2 */"\x7D\x03"\
		/* mov al,01 */                             "\xB0\x01",
		//Patch:
		/* nop (2 bytes) */                         "\x66\x90"\
		/* mov al 07 */                             "\xB0\x07"
	);

	// This works just like the above patch, but applies to a different check
	// which is used basically everywhere else in the game, as far as I can
	// tell. The only icon this doesn't affect is the one in the Ranked
	// queue/search menu.
	TogglePatch(
		"Force all other Ranked tier icons to be Master",
		process, moduleBase, 0x4E18832, 4,
		// Original:
		/* jnl Rivals2-Win64-Shipping.exe+4E18837 */"\x7D\x03"\
		/* mov al,01 */                             "\xB0\x01",
		//Patch:
		/* nop (2 bytes) */                         "\x66\x90"\
		/* mov al 07 */                             "\xB0\x07"
	);

	// This hides most instances of Elo being displayed. Instead, it's like an
	// empty string is there instead. I think this skips calling the procedure
	// which would actually render the string to begin with, but I'm not 100%
	// sure. This works in the main menu, when selecting the Ranked queue, and
	// during online matches, but does not hide your previous and new Elo
	// displayed after a ranked set.
	TogglePatch(
		"Hide all Elo numbers other than post-set change values",
		process, moduleBase, 0x4E188A0, 5,
		// Original:
		/* call Rivals2-Win64-Shipping.exe+1213DC0 */"\xE8\x1B\xB5\x3F\xFC",
		//Patch:
		/* nop (5 bytes) */                          "\x0F\x1F\x44\x00\x01"
	);

	// This hides your previous and new Elo displayed after a ranked set.
	TogglePatch(
		"Hide post-set Elo display",
		process, moduleBase, 0x4DCBF58, 5,
		// Original:
		/* call Rivals2-Win64-Shipping.exe+4DBDCC0 */"\xE8\x63\x1D\xFF\xFF",
		//Patch:
		/* nop (5 bytes) */                          "\x0F\x1F\x44\x00\x01"
	);

	CloseHandle(process);
}