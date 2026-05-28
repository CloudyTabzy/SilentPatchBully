#include "SystemInfo.h"

#include <stdio.h>
#include <wchar.h>
#include <psapi.h>
#include <shlwapi.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace CrashReporter
{
	void CollectOSInfo( OSInfo& out )
	{
		memset( &out, 0, sizeof(out) );

		RTL_OSVERSIONINFOW osvi = { sizeof(osvi) };
		// Dynamically load RtlGetVersion to avoid linker dependency on ntdll.lib (needed for XP SDK)
		using RtlGetVersion_t = LONG (WINAPI*)( PRTL_OSVERSIONINFOW );
		auto pRtlGetVersion = (RtlGetVersion_t)GetProcAddress( GetModuleHandleW( L"ntdll.dll" ), "RtlGetVersion" );
		if ( pRtlGetVersion != nullptr && pRtlGetVersion( &osvi ) == 0 )
		{
			out.major = osvi.dwMajorVersion;
			out.minor = osvi.dwMinorVersion;
			out.build = osvi.dwBuildNumber;
		}

		// Detect Wine
		HMODULE hNtdll = GetModuleHandleW( L"ntdll.dll" );
		if ( hNtdll != nullptr )
		{
			out.isWine = (GetProcAddress( hNtdll, "wine_get_version" ) != nullptr);
		}

		// Build a friendly edition string
		if ( out.isWine )
		{
			wcscpy_s( out.edition, L"Wine/Proton" );
		}
		else if ( out.major == 10 && out.minor == 0 )
		{
			if ( out.build >= 22000 )
				wcscpy_s( out.edition, L"Windows 11" );
			else
				wcscpy_s( out.edition, L"Windows 10" );
		}
		else if ( out.major == 6 && out.minor == 3 )
		{
			wcscpy_s( out.edition, L"Windows 8.1" );
		}
		else if ( out.major == 6 && out.minor == 2 )
		{
			wcscpy_s( out.edition, L"Windows 8" );
		}
		else if ( out.major == 6 && out.minor == 1 )
		{
			wcscpy_s( out.edition, L"Windows 7" );
		}
		else if ( out.major == 6 && out.minor == 0 )
		{
			wcscpy_s( out.edition, L"Windows Vista" );
		}
		else if ( out.major == 5 && out.minor == 1 )
		{
			wcscpy_s( out.edition, L"Windows XP" );
		}
		else
		{
			swprintf_s( out.edition, L"Windows %u.%u", out.major, out.minor );
		}
	}

	void CollectMemoryInfo( MemoryInfo& out, bool checkLAA )
	{
		memset( &out, 0, sizeof(out) );

		MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
		if ( GlobalMemoryStatusEx( &memStatus ) )
		{
			out.totalPhysicalMB = memStatus.ullTotalPhys / (1024 * 1024);
			out.availPhysicalMB = memStatus.ullAvailPhys / (1024 * 1024);
		}

		PROCESS_MEMORY_COUNTERS pmc = {};
		if ( GetProcessMemoryInfo( GetCurrentProcess(), &pmc, sizeof(pmc) ) )
		{
			out.processWorkingSetMB = pmc.WorkingSetSize / (1024 * 1024);
			out.processVirtualMB = pmc.PagefileUsage / (1024 * 1024);
		}

		if ( checkLAA )
		{
			out.largeAddressAware = IsLargeAddressAware( GetModuleHandle( nullptr ) );
		}
	}

	void CollectGPUInfo( GPUInfo& out )
	{
		memset( &out, 0, sizeof(out) );

		// Try DXGI first (most reliable on Win7+)
		HMODULE hDxgi = LoadLibraryW( L"dxgi.dll" );
		if ( hDxgi != nullptr )
		{
			using CreateDXGIFactory1_t = HRESULT (WINAPI*)( REFIID, void** );
			auto pCreateDXGIFactory1 = (CreateDXGIFactory1_t)GetProcAddress( hDxgi, "CreateDXGIFactory1" );
			if ( pCreateDXGIFactory1 != nullptr )
			{
				struct IDXGIAdapter;
				struct IDXGIFactory;
				const IID IID_IDXGIFactory1 = { 0x770aae78, 0xf26f, 0x4dba, { 0xa8, 0x29, 0x25, 0x3c, 0x83, 0x31, 0x8b, 0xf7 } };
				IDXGIFactory* pFactory = nullptr;
				if ( SUCCEEDED( pCreateDXGIFactory1( IID_IDXGIFactory1, (void**)&pFactory ) ) && pFactory != nullptr )
				{
					struct IDXGIAdapter1;
					const IID IID_IDXGIAdapter1 = { 0x29038f61, 0x3839, 0x4626, { 0x91, 0xfd, 0x08, 0x68, 0x79, 0x01, 0x1a, 0x05 } };
					void* pAdapter = nullptr;
					// Use vtable call: EnumAdapters1 is at index 7 in IDXGIFactory1
					using EnumAdapters1_t = HRESULT (__stdcall*)( void*, UINT, void** );
					void** vtable = *(void***)pFactory;
					auto pEnumAdapters1 = (EnumAdapters1_t)vtable[7];
					if ( SUCCEEDED( pEnumAdapters1( pFactory, 0, &pAdapter ) ) && pAdapter != nullptr )
					{
						// IDXGIAdapter1::GetDesc1 at index 10
						struct DXGI_ADAPTER_DESC1
						{
							WCHAR Description[128];
							UINT VendorId;
							UINT DeviceId;
							UINT SubSysId;
							UINT Revision;
							SIZE_T DedicatedVideoMemory;
							SIZE_T DedicatedSystemMemory;
							SIZE_T SharedSystemMemory;
							LUID AdapterLuid;
							UINT Flags;
						};
						using GetDesc1_t = HRESULT (__stdcall*)( void*, DXGI_ADAPTER_DESC1* );
						void** adapterVtable = *(void***)pAdapter;
						auto pGetDesc1 = (GetDesc1_t)adapterVtable[10];
						DXGI_ADAPTER_DESC1 desc = {};
						if ( SUCCEEDED( pGetDesc1( pAdapter, &desc ) ) )
						{
							wcscpy_s( out.adapterName, desc.Description );
							out.vramMB = desc.DedicatedVideoMemory / (1024 * 1024);
						}
						// Release adapter
						using Release_t = ULONG (__stdcall*)( void* );
						auto pRelease = (Release_t)adapterVtable[2];
						pRelease( pAdapter );
					}
					// Release factory
					using Release_t = ULONG (__stdcall*)( void* );
					auto pRelease = (Release_t)vtable[2];
					pRelease( pFactory );
				}
			}
			FreeLibrary( hDxgi );
		}

		// Fallback to GDI display device
		if ( out.adapterName[0] == L'\0' )
		{
			DISPLAY_DEVICEW dd = { sizeof(dd) };
			if ( EnumDisplayDevicesW( nullptr, 0, &dd, 0 ) )
			{
				wcscpy_s( out.adapterName, dd.DeviceString );
			}
		}

		// Driver date from registry (best effort)
		HKEY hKey;
		if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}",
			0, KEY_READ, &hKey ) == ERROR_SUCCESS )
		{
			WCHAR subkeyName[256];
			DWORD index = 0, nameLen = 256;
			while ( RegEnumKeyExW( hKey, index++, subkeyName, &nameLen, nullptr, nullptr, nullptr, nullptr ) == ERROR_SUCCESS )
			{
				nameLen = 256;
				HKEY hSubKey;
				if ( RegOpenKeyExW( hKey, subkeyName, 0, KEY_READ, &hSubKey ) == ERROR_SUCCESS )
				{
					WCHAR driverDesc[256] = {};
					DWORD size = sizeof(driverDesc);
					if ( RegQueryValueExW( hSubKey, L"DriverDesc", nullptr, nullptr, (LPBYTE)driverDesc, &size ) == ERROR_SUCCESS )
					{
						// Simple substring match
						if ( wcsstr( out.adapterName, driverDesc ) != nullptr || wcsstr( driverDesc, out.adapterName ) != nullptr )
						{
							WCHAR driverDate[32] = {};
							size = sizeof(driverDate);
							if ( RegQueryValueExW( hSubKey, L"DriverDate", nullptr, nullptr, (LPBYTE)driverDate, &size ) == ERROR_SUCCESS )
							{
								wcscpy_s( out.driverDate, driverDate );
							}
							RegCloseKey( hSubKey );
							break;
						}
					}
					RegCloseKey( hSubKey );
				}
			}
			RegCloseKey( hKey );
		}
	}

	void CollectProcessInfo( ProcessInfo& out )
	{
		memset( &out, 0, sizeof(out) );
		out.pid = GetCurrentProcessId();
		GetModuleFileNameW( nullptr, out.exePath, MAX_PATH );
	}

	bool IsLargeAddressAware( HMODULE hModule )
	{
		if ( hModule == nullptr ) return false;

		auto* dosHeader = (PIMAGE_DOS_HEADER)hModule;
		if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) return false;

		auto* ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)hModule + dosHeader->e_lfanew);
		if ( ntHeader->Signature != IMAGE_NT_SIGNATURE ) return false;

		return (ntHeader->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
	}
}
