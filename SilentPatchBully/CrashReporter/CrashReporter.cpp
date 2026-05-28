#include "CrashReporter.h"
#include "SystemInfo.h"

#include <windows.h>
#include <intrin.h>
#include <dbghelp.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace CrashReporter
{
	static HINSTANCE g_hModule = nullptr;
	static bool g_enabled = true;
	static volatile LONG g_installed = 0;
	static DWORD g_startTick = 0;
	static char g_gameState[256] = { 0 };

	// Version info from build system
	extern "C" uint32_t GetBuildNumber();

	void SetEnabled( bool enable )
	{
		g_enabled = enable;
	}

	bool IsEnabled()
	{
		return g_enabled;
	}

	void SetGameState( const char* state )
	{
		if ( state == nullptr ) return;
		size_t len = strlen( state );
		if ( len >= sizeof(g_gameState) ) len = sizeof(g_gameState) - 1;
		memcpy( (void*)g_gameState, state, len );
		((char*)g_gameState)[len] = '\0';
	}

	// ------------------------------------------------------------------
	// Helper: ensure directory exists
	// ------------------------------------------------------------------
	static bool EnsureDirectory( const wchar_t* path )
	{
		DWORD attribs = GetFileAttributesW( path );
		if ( attribs != INVALID_FILE_ATTRIBUTES && (attribs & FILE_ATTRIBUTE_DIRECTORY) )
			return true;
		return CreateDirectoryW( path, nullptr ) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
	}

	// ------------------------------------------------------------------
	// Helper: write JSON string escaping
	// ------------------------------------------------------------------
	static void WriteJsonString( FILE* f, const char* str )
	{
		fputc( '"', f );
		if ( str != nullptr )
		{
			for ( const char* p = str; *p != '\0'; ++p )
			{
				switch ( *p )
				{
				case '"':  fputs( "\\\"", f ); break;
				case '\\': fputs( "\\\\", f ); break;
				case '\b': fputs( "\\b", f ); break;
				case '\f': fputs( "\\f", f ); break;
				case '\n': fputs( "\\n", f ); break;
				case '\r': fputs( "\\r", f ); break;
				case '\t': fputs( "\\t", f ); break;
				default:
					if ( (unsigned char)*p < 0x20 )
						fprintf( f, "\\u%04x", (unsigned char)*p );
					else
						fputc( *p, f );
					break;
				}
			}
		}
		fputc( '"', f );
	}

	static void WriteJsonWString( FILE* f, const wchar_t* wstr )
	{
		char utf8[512] = { 0 };
		if ( wstr != nullptr )
		{
			WideCharToMultiByte( CP_UTF8, 0, wstr, -1, utf8, sizeof(utf8), nullptr, nullptr );
		}
		WriteJsonString( f, utf8 );
	}

	// ------------------------------------------------------------------
	// Minidump callback: strip heap / private memory
	// ------------------------------------------------------------------
	static BOOL CALLBACK MiniDumpCallback( PVOID,
		const PMINIDUMP_CALLBACK_INPUT CallbackInput,
		PMINIDUMP_CALLBACK_OUTPUT CallbackOutput )
	{
		if ( CallbackInput == nullptr || CallbackOutput == nullptr )
			return FALSE;

		switch ( CallbackInput->CallbackType )
		{
			case IncludeModuleCallback:
			case IncludeThreadCallback:
			case ThreadCallback:
			case ModuleCallback:
				return TRUE;

			case MemoryCallback:
				// Don't include arbitrary memory regions
				return FALSE;

			case CancelCallback:
				return FALSE;
		}
		return FALSE;
	}

	// ------------------------------------------------------------------
	// Stack trace with StackWalk64 + symbol fallback
	// ------------------------------------------------------------------
	struct StackFrame
	{
		uint32_t addr;
		char moduleName[64];
		char symbolName[256];
		uint32_t offset;
	};

	static int CaptureStackTrace( CONTEXT* ctx, StackFrame* frames, int maxFrames )
	{
		if ( maxFrames <= 0 ) return 0;

		HMODULE hDbgHelp = LoadLibraryA( "dbghelp.dll" );
		if ( hDbgHelp == nullptr )
		{
			// Fallback to EBP walk
			int count = 0;
			__try
			{
				uint32_t* frame = (uint32_t*)ctx->Ebp;
				for ( int i = 0; i < maxFrames && frame != nullptr; i++ )
				{
					uint32_t retAddr = frame[1];
					if ( retAddr == 0 || retAddr < 0x10000 ) break;

					frames[count].addr = retAddr;
					frames[count].moduleName[0] = '\0';
					frames[count].symbolName[0] = '\0';
					frames[count].offset = 0;

					HMODULE hFrameMod = nullptr;
					if ( GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)retAddr, &hFrameMod ) )
					{
						char modPath[MAX_PATH] = { 0 };
						GetModuleFileNameA( hFrameMod, modPath, MAX_PATH );
						char* bn = strrchr( modPath, '\\' );
						strncpy_s( frames[count].moduleName, bn != nullptr ? bn + 1 : modPath, _TRUNCATE );
						frames[count].offset = (uint32_t)(retAddr - (uintptr_t)hFrameMod);
					}
					count++;

					uint32_t nextFrame = frame[0];
					if ( nextFrame <= (uint32_t)frame || nextFrame > ctx->Esp + 0x100000 ) break;
					frame = (uint32_t*)nextFrame;
				}
			}
			__except ( EXCEPTION_EXECUTE_HANDLER ) {}
			return count;
		}

		using SymInitialize_t = BOOL (WINAPI*)( HANDLE, PCSTR, BOOL );
		using SymCleanup_t = BOOL (WINAPI*)( HANDLE );
		using StackWalk64_t = BOOL (WINAPI*)( DWORD, HANDLE, HANDLE, LPSTACKFRAME64, PVOID, PREAD_PROCESS_MEMORY_ROUTINE64,
			PFUNCTION_TABLE_ACCESS_ROUTINE64, PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64 );
		using SymFromAddr_t = BOOL (WINAPI*)( HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO );
		using SymGetModuleBase64_t = DWORD64 (WINAPI*)( HANDLE, DWORD64 );
		using SymFunctionTableAccess64_t = PVOID (WINAPI*)( HANDLE, DWORD64 );
		using SymSetOptions_t = DWORD (WINAPI*)( DWORD );

		auto pSymInitialize = (SymInitialize_t)GetProcAddress( hDbgHelp, "SymInitialize" );
		auto pSymCleanup = (SymCleanup_t)GetProcAddress( hDbgHelp, "SymCleanup" );
		auto pStackWalk64 = (StackWalk64_t)GetProcAddress( hDbgHelp, "StackWalk64" );
		auto pSymFromAddr = (SymFromAddr_t)GetProcAddress( hDbgHelp, "SymFromAddr" );
		auto pSymGetModuleBase64 = (SymGetModuleBase64_t)GetProcAddress( hDbgHelp, "SymGetModuleBase64" );
		auto pSymFunctionTableAccess64 = (SymFunctionTableAccess64_t)GetProcAddress( hDbgHelp, "SymFunctionTableAccess64" );
		auto pSymSetOptions = (SymSetOptions_t)GetProcAddress( hDbgHelp, "SymSetOptions" );

		if ( pSymInitialize == nullptr || pStackWalk64 == nullptr )
		{
			FreeLibrary( hDbgHelp );
			return 0;
		}

		HANDLE hProcess = GetCurrentProcess();
		if ( pSymSetOptions )
			pSymSetOptions( SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES );
		pSymInitialize( hProcess, nullptr, TRUE );

		STACKFRAME64 stackFrame = {};
		DWORD machineType = IMAGE_FILE_MACHINE_I386;

		stackFrame.AddrPC.Offset = ctx->Eip;
		stackFrame.AddrPC.Mode = AddrModeFlat;
		stackFrame.AddrFrame.Offset = ctx->Ebp;
		stackFrame.AddrFrame.Mode = AddrModeFlat;
		stackFrame.AddrStack.Offset = ctx->Esp;
		stackFrame.AddrStack.Mode = AddrModeFlat;

		int count = 0;
		CONTEXT walkCtx = *ctx;
		for ( int i = 0; i < maxFrames; i++ )
		{
			if ( !pStackWalk64( machineType, hProcess, GetCurrentThread(), &stackFrame, &walkCtx,
				nullptr, pSymFunctionTableAccess64, pSymGetModuleBase64, nullptr ) )
				break;

			if ( stackFrame.AddrPC.Offset == 0 )
				break;

			frames[count].addr = (uint32_t)stackFrame.AddrPC.Offset;
			frames[count].moduleName[0] = '\0';
			frames[count].symbolName[0] = '\0';
			frames[count].offset = 0;

			// Module name
			DWORD64 modBase = pSymGetModuleBase64 ? pSymGetModuleBase64( hProcess, stackFrame.AddrPC.Offset ) : 0;
			if ( modBase != 0 )
			{
				frames[count].offset = (uint32_t)(stackFrame.AddrPC.Offset - modBase);
				HMODULE hMod = nullptr;
				if ( GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)(uintptr_t)stackFrame.AddrPC.Offset, &hMod ) )
				{
					char modPath[MAX_PATH] = { 0 };
					GetModuleFileNameA( hMod, modPath, MAX_PATH );
					char* bn = strrchr( modPath, '\\' );
					strncpy_s( frames[count].moduleName, bn != nullptr ? bn + 1 : modPath, _TRUNCATE );
				}
			}

			// Symbol name
			if ( pSymFromAddr != nullptr )
			{
				alignas(16) char symBuffer[sizeof(SYMBOL_INFO) + 255] = {};
				PSYMBOL_INFO pSym = (PSYMBOL_INFO)symBuffer;
				pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
				pSym->MaxNameLen = 256;
				DWORD64 disp = 0;
				if ( pSymFromAddr( hProcess, stackFrame.AddrPC.Offset, &disp, pSym ) )
				{
					strncpy_s( frames[count].symbolName, pSym->Name, _TRUNCATE );
				}
			}

			count++;
		}

		pSymCleanup( hProcess );
		FreeLibrary( hDbgHelp );
		return count;
	}

	// ------------------------------------------------------------------
	// Enumerate loaded modules
	// ------------------------------------------------------------------
	struct ModuleEntry
	{
		char name[MAX_PATH];
		char path[MAX_PATH];
		uint32_t base;
		uint32_t size;
	};

	static int EnumerateModules( ModuleEntry* entries, int maxEntries )
	{
		HMODULE hMods[256];
		DWORD cbNeeded;
		HANDLE hProcess = GetCurrentProcess();
		int count = 0;

		if ( EnumProcessModules( hProcess, hMods, sizeof(hMods), &cbNeeded ) )
		{
			int numMods = cbNeeded / sizeof(HMODULE);
			if ( numMods > maxEntries ) numMods = maxEntries;
			for ( int i = 0; i < numMods; i++ )
			{
				MODULEINFO modInfo = {};
				if ( GetModuleInformation( hProcess, hMods[i], &modInfo, sizeof(modInfo) ) )
				{
					entries[count].base = (uint32_t)(uintptr_t)modInfo.lpBaseOfDll;
					entries[count].size = (uint32_t)modInfo.SizeOfImage;

					char fullPath[MAX_PATH] = {};
					GetModuleFileNameExA( hProcess, hMods[i], fullPath, MAX_PATH );
					strncpy_s( entries[count].path, fullPath, _TRUNCATE );

					char* bn = strrchr( fullPath, '\\' );
					strncpy_s( entries[count].name, bn != nullptr ? bn + 1 : fullPath, _TRUNCATE );
					count++;
				}
			}
		}
		return count;
	}

	// ------------------------------------------------------------------
	// Write JSON crash report
	// ------------------------------------------------------------------
	static void WriteCrashJson( const wchar_t* path, DWORD exceptionCode, PVOID faultAddr,
		CONTEXT* ctx, const StackFrame* frames, int frameCount,
		const OSInfo& os, const MemoryInfo& mem, const GPUInfo& gpu, const ProcessInfo& proc )
	{
		FILE* f = nullptr;
		if ( _wfopen_s( &f, path, L"w" ) != 0 || f == nullptr )
			return;

		// SilentPatch version
		uint32_t build = GetBuildNumber();
		uint32_t revision = (build >> 8) & 0xFF;
		uint32_t buildId = build & 0xFF;

		// Timestamp
		SYSTEMTIME st;
		GetLocalTime( &st );
		char timestamp[64];
		snprintf( timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond );

		fprintf( f, "{\n" );

		// silentpatch block
		fprintf( f, "  \"silentpatch\": {\n" );
		fprintf( f, "    \"version\": \"%u.%u.%u\",\n", revision, buildId, 0 );
		fprintf( f, "    \"build\": %u,\n", buildId );
		fprintf( f, "    \"revision\": %u,\n", revision );
		fprintf( f, "    \"game\": " );
		WriteJsonString( f, "Bully: Scholarship Edition" );
		fprintf( f, "\n  },\n" );

		// crash block
		fprintf( f, "  \"crash\": {\n" );
		fprintf( f, "    \"timestamp\": " );
		WriteJsonString( f, timestamp );
		fprintf( f, ",\n" );
		fprintf( f, "    \"exception_code\": \"0x%08X\",\n", exceptionCode );
		fprintf( f, "    \"fault_address\": \"0x%08X\"", (uint32_t)faultAddr );

		HMODULE hFaultMod = nullptr;
		if ( GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)faultAddr, &hFaultMod ) )
		{
			fprintf( f, ",\n    \"fault_module\": " );
			char modPath[MAX_PATH] = { 0 };
			GetModuleFileNameA( hFaultMod, modPath, MAX_PATH );
			char* bn = strrchr( modPath, '\\' );
			WriteJsonString( f, bn != nullptr ? bn + 1 : modPath );
			fprintf( f, ",\n    \"fault_rva\": \"0x%08X\"", (uint32_t)((uintptr_t)faultAddr - (uintptr_t)hFaultMod) );
		}

		// AV details
		if ( exceptionCode == EXCEPTION_ACCESS_VIOLATION )
		{
			// We don't have ExceptionInformation here, skip it in JSON to keep it simple
			// The minidump and text log have the full details
		}

		fprintf( f, "\n  },\n" );

		// registers block
		fprintf( f, "  \"registers\": {\n" );
		fprintf( f, "    \"eax\": \"0x%08X\",\n", ctx->Eax );
		fprintf( f, "    \"ecx\": \"0x%08X\",\n", ctx->Ecx );
		fprintf( f, "    \"edx\": \"0x%08X\",\n", ctx->Edx );
		fprintf( f, "    \"ebx\": \"0x%08X\",\n", ctx->Ebx );
		fprintf( f, "    \"esp\": \"0x%08X\",\n", ctx->Esp );
		fprintf( f, "    \"ebp\": \"0x%08X\",\n", ctx->Ebp );
		fprintf( f, "    \"esi\": \"0x%08X\",\n", ctx->Esi );
		fprintf( f, "    \"edi\": \"0x%08X\",\n", ctx->Edi );
		fprintf( f, "    \"eip\": \"0x%08X\",\n", ctx->Eip );
		fprintf( f, "    \"eflags\": \"0x%08X\"\n", ctx->EFlags );
		fprintf( f, "  },\n" );

		// stack_trace block
		fprintf( f, "  \"stack_trace\": [\n" );
		for ( int i = 0; i < frameCount; i++ )
		{
			fprintf( f, "    {\n" );
			fprintf( f, "      \"frame\": %d,\n", i );
			fprintf( f, "      \"address\": \"0x%08X\",\n", frames[i].addr );
			fprintf( f, "      \"module\": " );
			WriteJsonString( f, frames[i].moduleName );
			fprintf( f, ",\n" );
			fprintf( f, "      \"module_rva\": \"0x%08X\",\n", frames[i].offset );
			fprintf( f, "      \"symbol\": " );
			WriteJsonString( f, frames[i].symbolName );
			fprintf( f, "\n    }" );
			if ( i + 1 < frameCount ) fprintf( f, "," );
			fprintf( f, "\n" );
		}
		fprintf( f, "  ],\n" );

		// game block
		fprintf( f, "  \"game\": {\n" );
		DWORD runtimeSecs = (GetTickCount() - g_startTick) / 1000;
		fprintf( f, "    \"runtime_seconds\": %lu,\n", runtimeSecs );
		fprintf( f, "    \"state\": " );
		WriteJsonString( f, g_gameState[0] != '\0' ? g_gameState : "unknown" );
		fprintf( f, "\n  },\n" );

		// os block
		fprintf( f, "  \"os\": {\n" );
		fprintf( f, "    \"platform\": " );
		WriteJsonString( f, "windows" );
		fprintf( f, ",\n" );
		fprintf( f, "    \"version\": \"%u.%u.%u\",\n", os.major, os.minor, os.build );
		fprintf( f, "    \"edition\": " );
		WriteJsonWString( f, os.edition );
		fprintf( f, ",\n" );
		fprintf( f, "    \"is_wine\": %s\n", os.isWine ? "true" : "false" );
		fprintf( f, "  },\n" );

		// memory block
		fprintf( f, "  \"memory\": {\n" );
		fprintf( f, "    \"total_physical_mb\": %llu,\n", mem.totalPhysicalMB );
		fprintf( f, "    \"available_physical_mb\": %llu,\n", mem.availPhysicalMB );
		fprintf( f, "    \"process_working_set_mb\": %llu,\n", mem.processWorkingSetMB );
		fprintf( f, "    \"process_virtual_mb\": %llu,\n", mem.processVirtualMB );
		fprintf( f, "    \"large_address_aware\": %s\n", mem.largeAddressAware ? "true" : "false" );
		fprintf( f, "  },\n" );

		// modules block
		ModuleEntry modules[256];
		int moduleCount = EnumerateModules( modules, 256 );
		fprintf( f, "  \"modules\": [\n" );
		for ( int i = 0; i < moduleCount; i++ )
		{
			fprintf( f, "    {\n" );
			fprintf( f, "      \"name\": " );
			WriteJsonString( f, modules[i].name );
			fprintf( f, ",\n" );
			fprintf( f, "      \"base\": \"0x%08X\",\n", modules[i].base );
			fprintf( f, "      \"size\": %lu\n", modules[i].size );
			fprintf( f, "    }" );
			if ( i + 1 < moduleCount ) fprintf( f, "," );
			fprintf( f, "\n" );
		}
		fprintf( f, "  ],\n" );

		// gpu block
		fprintf( f, "  \"gpu\": {\n" );
		fprintf( f, "    \"driver_date\": " );
		WriteJsonWString( f, gpu.driverDate );
		fprintf( f, ",\n" );
		fprintf( f, "    \"adapters\": [\n" );
		for ( uint32_t i = 0; i < gpu.adapterCount; i++ )
		{
			fprintf( f, "      {\n" );
			fprintf( f, "        \"name\": " );
			WriteJsonWString( f, gpu.adapters[i].name );
			fprintf( f, ",\n" );
			fprintf( f, "        \"vram_mb\": %llu,\n", gpu.adapters[i].vramMB );
			fprintf( f, "        \"shared_mb\": %llu,\n", gpu.adapters[i].sharedMB );
			fprintf( f, "        \"is_integrated\": %s\n", gpu.adapters[i].isIntegrated ? "true" : "false" );
			fprintf( f, "      }" );
			if ( i + 1 < gpu.adapterCount ) fprintf( f, "," );
			fprintf( f, "\n" );
		}
		fprintf( f, "    ]\n" );
		fprintf( f, "  },\n" );

		// process block
		fprintf( f, "  \"process\": {\n" );
		fprintf( f, "    \"pid\": %lu,\n", proc.pid );
		fprintf( f, "    \"exe_path\": " );
		WriteJsonWString( f, proc.exePath );
		fprintf( f, "\n  }\n" );

		fprintf( f, "}\n" );
		fclose( f );
	}

	// ------------------------------------------------------------------
	// Write legacy text crash log (retained for backward compatibility)
	// ------------------------------------------------------------------
	static void WriteCrashLog( const wchar_t* path, DWORD exceptionCode, PVOID faultAddr,
		CONTEXT* ctx, const StackFrame* frames, int frameCount )
	{
		FILE* f = nullptr;
		if ( _wfopen_s( &f, path, L"w" ) != 0 || f == nullptr )
			return;

		SYSTEMTIME st;
		GetLocalTime( &st );
		fprintf( f, "========================================\n" );
		fprintf( f, "Crash detected at %04d-%02d-%02d %02d:%02d:%02d.%03d\n",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds );
		fprintf( f, "Exception Code: 0x%08X\n", exceptionCode );
		fprintf( f, "Fault Address:  0x%08X\n", (uint32_t)faultAddr );

		HMODULE hMod = nullptr;
		if ( GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)faultAddr, &hMod ) )
		{
			char modName[MAX_PATH] = { 0 };
			GetModuleFileNameA( hMod, modName, MAX_PATH );
			char* bn = strrchr( modName, '\\' );
			fprintf( f, "Fault Module:   %s (base: 0x%08X)\n",
				bn != nullptr ? bn + 1 : modName, (uint32_t)hMod );
			fprintf( f, "Image RVA:      0x%08X\n", (uint32_t)((uintptr_t)faultAddr - (uintptr_t)hMod) );
		}

		fprintf( f, "\nRegister State:\n" );
		fprintf( f, "  EAX: 0x%08X  ECX: 0x%08X  EDX: 0x%08X  EBX: 0x%08X\n",
			ctx->Eax, ctx->Ecx, ctx->Edx, ctx->Ebx );
		fprintf( f, "  ESP: 0x%08X  EBP: 0x%08X  ESI: 0x%08X  EDI: 0x%08X\n",
			ctx->Esp, ctx->Ebp, ctx->Esi, ctx->Edi );
		fprintf( f, "  EIP: 0x%08X  EFL: 0x%08X\n",
			ctx->Eip, ctx->EFlags );

		fprintf( f, "\nStack Trace:\n" );
		for ( int i = 0; i < frameCount; i++ )
		{
			if ( frames[i].symbolName[0] != '\0' )
			{
				fprintf( f, "  [%02d] 0x%08X  %s!%s+0x%X\n", i, frames[i].addr,
					frames[i].moduleName, frames[i].symbolName, frames[i].offset );
			}
			else
			{
				fprintf( f, "  [%02d] 0x%08X  (%s+0x%08X)\n", i, frames[i].addr,
					frames[i].moduleName, frames[i].offset );
			}
		}

		fprintf( f, "========================================\n" );
		fclose( f );
	}

	// ------------------------------------------------------------------
	// Write filtered minidump
	// ------------------------------------------------------------------
	static void WriteMiniDump( const wchar_t* path, EXCEPTION_POINTERS* exceptionInfo )
	{
		HMODULE hDbgHelp = LoadLibraryA( "dbghelp.dll" );
		if ( hDbgHelp == nullptr ) return;

		using MiniDumpWriteDump_t = BOOL (WINAPI*)( HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
			PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION,
			PMINIDUMP_CALLBACK_INFORMATION );
		auto pMiniDumpWriteDump = (MiniDumpWriteDump_t)GetProcAddress( hDbgHelp, "MiniDumpWriteDump" );
		if ( pMiniDumpWriteDump == nullptr )
		{
			FreeLibrary( hDbgHelp );
			return;
		}

		HANDLE hFile = CreateFileW( path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
		if ( hFile == INVALID_HANDLE_VALUE )
		{
			FreeLibrary( hDbgHelp );
			return;
		}

		MINIDUMP_EXCEPTION_INFORMATION mei = {};
		mei.ThreadId = GetCurrentThreadId();
		mei.ExceptionPointers = exceptionInfo;
		mei.ClientPointers = FALSE;

		MINIDUMP_CALLBACK_INFORMATION mci = {};
		mci.CallbackRoutine = MiniDumpCallback;
		mci.CallbackParam = nullptr;

		MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory |
			MiniDumpScanMemory);

		pMiniDumpWriteDump( GetCurrentProcess(), GetCurrentProcessId(), hFile, dumpType, &mei, nullptr, &mci );

		CloseHandle( hFile );
		FreeLibrary( hDbgHelp );
	}

	// ------------------------------------------------------------------
	// Vectored Exception Handler
	// ------------------------------------------------------------------
	static LONG WINAPI VectoredExceptionHandler( EXCEPTION_POINTERS* ExceptionInfo )
	{
		if ( !g_enabled )
			return EXCEPTION_CONTINUE_SEARCH;

		DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;
		if ( code != EXCEPTION_ACCESS_VIOLATION &&
			 code != EXCEPTION_ILLEGAL_INSTRUCTION &&
			 code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
			 code != EXCEPTION_PRIV_INSTRUCTION )
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		PVOID faultAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
		CONTEXT* ctx = ExceptionInfo->ContextRecord;

		// Only log crashes in the game executable or our own module
		HMODULE hMod = nullptr;
		if ( !GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)faultAddr, &hMod ) )
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		HMODULE hGame = GetModuleHandle( nullptr );
		HMODULE hSelf = g_hModule;
		if ( hMod != hGame && hMod != hSelf )
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// Build base path in the game executable's directory
		wchar_t gamePath[MAX_PATH];
		if ( GetModuleFileNameW( GetModuleHandle(nullptr), gamePath, MAX_PATH ) == 0 )
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// Strip filename to get directory
		wchar_t* lastSlash = wcsrchr( gamePath, L'\\' );
		if ( lastSlash != nullptr )
			*(lastSlash + 1) = L'\0';

		// Create crash_reports directory
		wchar_t reportsDir[MAX_PATH];
		swprintf_s( reportsDir, L"%scrash_reports\\", gamePath );
		EnsureDirectory( reportsDir );

		// Create timestamped subdirectory
		SYSTEMTIME st;
		GetLocalTime( &st );
		wchar_t crashDir[MAX_PATH];
		swprintf_s( crashDir, L"%scrash_%04d-%02d-%02d_%02d%02d%02d\\",
			reportsDir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond );
		EnsureDirectory( crashDir );

		// Collect system info
		OSInfo osInfo;
		MemoryInfo memInfo;
		GPUInfo gpuInfo;
		ProcessInfo procInfo;
		CollectOSInfo( osInfo );
		CollectMemoryInfo( memInfo, true );
		CollectGPUInfo( gpuInfo );
		CollectProcessInfo( procInfo );

		// Capture stack trace
		StackFrame frames[64];
		int frameCount = CaptureStackTrace( ctx, frames, 64 );

		// Write JSON report
		wchar_t jsonPath[MAX_PATH];
		swprintf_s( jsonPath, L"%scrash.json", crashDir );
		WriteCrashJson( jsonPath, code, faultAddr, ctx, frames, frameCount, osInfo, memInfo, gpuInfo, procInfo );

		// Write legacy text log
		wchar_t logPath[MAX_PATH];
		swprintf_s( logPath, L"%scrash.txt", crashDir );
		WriteCrashLog( logPath, code, faultAddr, ctx, frames, frameCount );

		// Write filtered minidump
		wchar_t dmpPath[MAX_PATH];
		swprintf_s( dmpPath, L"%scrash.dmp", crashDir );
		WriteMiniDump( dmpPath, ExceptionInfo );

		return EXCEPTION_CONTINUE_SEARCH;
	}

	// ------------------------------------------------------------------
	// Public API
	// ------------------------------------------------------------------
	void Install( HINSTANCE hModule )
	{
		if ( _InterlockedCompareExchange( &g_installed, 1, 0 ) != 0 )
			return;

		g_hModule = hModule;
		g_startTick = GetTickCount();
		AddVectoredExceptionHandler( 1, VectoredExceptionHandler );
	}
}
