extern "C" int XapiInitProcess();
extern "C" int XapiCallThreadNotifyRoutines(int);
extern "C" int XapiPAL50Incompatible();
extern "C" int XamTerminateTitle();
extern "C" int _mtinit();
extern "C" int _rtinit();
extern "C" int _cinit(int);
extern "C" int _cexit(int);
extern "C" int _CRT_INIT(...);
extern "C" int __CppXcptFilter(...);
extern "C" static int __proc_attached;
extern "C" VOID KeSweepIcacheRange(PVOID Address, DWORD cbBytes);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved);

BYTE g_SectionData[9] = { 'O', 'B', 'F', 'U', 'S', 'C', 'A', 'T', 'E' };

//CHANGE Entrypoint -> realEntryPoint
#pragma code_seg(push, r1, ".ptext")
__declspec(noinline) BOOL __cdecl realEntryPoint(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved) {
	BOOL retcode = TRUE;

	DWORD dwStart = *(DWORD*)(g_SectionData + 0);
	DWORD dwEnd = *(DWORD*)(g_SectionData + 4);
	BYTE bKey = *(BYTE*)(g_SectionData + 8);
	if (*(DWORD*)(g_SectionData + 0) != 'OBFU') {
		for (DWORD i = ~(dwStart ^ 0xA4AC24CE); i < ~(dwEnd ^ 0xA4AC24CE); i += 0x4){
			DWORD dwInstructionCache = *(DWORD*)i;
			DWORD dwNewInstruction = ((((dwInstructionCache) & 0xff000000) >> 24) | (((dwInstructionCache) & 0x00ff0000) >> 8) | (((dwInstructionCache) & 0x0000ff00) << 8) | (((dwInstructionCache) & 0x000000ff) << 24));
			*(DWORD*)i = dwNewInstruction;
		}
		for (DWORD i = ~(dwStart ^ 0xA4AC24CE); i < ~(dwEnd ^ 0xA4AC24CE); i++){
			*(BYTE*)(i) = *(BYTE*)(i) ^ (BYTE)~(bKey ^ 0xD3);
			if ((i % 4) == 0) {
				__dcbst(0, (void*)i);
				__sync();
				__isync();
			}
		}
	}

	if ((dwReason == DLL_PROCESS_DETACH) && (__proc_attached == 0)) {
		return FALSE;
	}
	if (dwReason == DLL_PROCESS_ATTACH || dwReason == DLL_THREAD_ATTACH) {
		if (retcode) {
			retcode = _CRT_INIT(hDllHandle, dwReason, lpreserved);
		}
		if (!retcode) {
			return FALSE;
		}
	}
	retcode = DllMain(hDllHandle, dwReason, lpreserved);
	if ((dwReason == DLL_PROCESS_ATTACH) && !retcode) {
		DllMain(hDllHandle, dwReason, lpreserved);
		_CRT_INIT(hDllHandle, DLL_PROCESS_DETACH, lpreserved);
	}
	if ((dwReason == DLL_PROCESS_DETACH) || (dwReason == DLL_THREAD_DETACH)) {
		if (_CRT_INIT(hDllHandle, dwReason, lpreserved) == FALSE) {
			retcode = FALSE;
		}
	}
	return retcode;
}
#pragma code_seg(pop, r1)
BOOL APIENTRY DllMain(HANDLE hInstDLL, ULONG fdwReason, LPVOID lpReserved) {
	pHandle = hInstDLL;
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH: {
			/*Dashboard Enforcer Dummy Thread*/
			HANDLE hThread; ULONG hThreadID;
			ExCreateThread(&hThread, FACILITY_NULL, &hThreadID, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)MainThread, FACILITY_NULL, 0x2);
			XSetThreadProcessor(hThread, FACILITY_ITF);
			ResumeThread(hThread);
			CloseHandle(hThread);
		} break;
	}
	return TRUE;
}
