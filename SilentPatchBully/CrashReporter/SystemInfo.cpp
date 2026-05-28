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

	// ------------------------------------------------------------------------
	// GPU classification helpers
	// ------------------------------------------------------------------------
	static bool IsAdapterNameKnown( const GPUInfo& info, const wchar_t* name )
	{
		for ( uint32_t i = 0; i < info.adapterCount; i++ )
		{
			if ( wcsstr( info.adapters[i].name, name ) != nullptr ||
			     wcsstr( name, info.adapters[i].name ) != nullptr )
			{
				return true;
			}
		}
		return false;
	}

	static bool ClassifyGpuAsIntegrated( const wchar_t* name, uint32_t vendorId )
	{
		// Intel: overwhelmingly integrated. Intel Arc is the rare discrete exception.
		if ( vendorId == 0x8086 )
		{
			if ( wcsstr( name, L"Arc" ) != nullptr )
				return false;
			return true;
		}

		// NVIDIA does not make x86 integrated GPUs (Tegra is ARM-only).
		if ( vendorId == 0x10DE )
			return false;

		// AMD: APUs (integrated) usually contain "Radeon Graphics" without a model number.
		//      Discrete cards have model series like RX, HD, R9, R7, etc.
		if ( vendorId == 0x1002 )
		{
			if ( wcsstr( name, L"Radeon Graphics" ) != nullptr &&
			     wcsstr( name, L"RX" ) == nullptr )
			{
				return true;
			}
			return false;
		}

		// Unknown vendor: guess by name heuristics
		if ( wcsstr( name, L"Intel" ) != nullptr && wcsstr( name, L"Arc" ) == nullptr )
			return true;
		if ( wcsstr( name, L"NVIDIA" ) != nullptr || wcsstr( name, L"GeForce" ) != nullptr )
			return false;
		if ( wcsstr( name, L"AMD" ) != nullptr || wcsstr( name, L"ATI" ) != nullptr || wcsstr( name, L"Radeon" ) != nullptr )
		{
			if ( wcsstr( name, L"Radeon Graphics" ) != nullptr && wcsstr( name, L"RX" ) == nullptr )
				return true;
			return false;
		}

		return false;
	}

	// Parse a PCI HardwareID/MatchingDeviceId string for the vendor ID.
	// Expected format: PCI\VEN_10DE&DEV_XXXX...
	static uint32_t ParseVendorIdFromPciString( const wchar_t* id )
	{
		if ( id == nullptr ) return 0;
		const wchar_t* ven = wcsstr( id, L"VEN_" );
		if ( ven != nullptr )
		{
			wchar_t* end = nullptr;
			unsigned long val = wcstoul( ven + 4, &end, 16 );
			if ( end != ven + 4 ) return static_cast<uint32_t>( val );
		}
		return 0;
	}

	// ------------------------------------------------------------------------
	// Layered GPU detection:
	//   1) DXGI          – best detail for active adapters (Win7+)
	//   2) Registry      – catches *all* installed display adapters, including
	//                      hidden Optimus dGPUs that DXGI omits (Win2000+)
	//   3) EnumDisplayDevices – legacy GDI fallback (Win2000+)
	// ------------------------------------------------------------------------
	void CollectGPUInfo( GPUInfo& out )
	{
		memset( &out, 0, sizeof(out) );

		// ----------------------------------------------------------------
		// Layer 1: DXGI
		// ----------------------------------------------------------------
		HMODULE hDxgi = LoadLibraryW( L"dxgi.dll" );
		if ( hDxgi != nullptr )
		{
			using CreateDXGIFactory1_t = HRESULT (WINAPI*)( REFIID, void** );
			auto pCreateDXGIFactory1 = (CreateDXGIFactory1_t)GetProcAddress( hDxgi, "CreateDXGIFactory1" );
			if ( pCreateDXGIFactory1 != nullptr )
			{
				const IID IID_IDXGIFactory1 = { 0x770aae78, 0xf26f, 0x4dba, { 0xa8, 0x29, 0x25, 0x3c, 0x83, 0x31, 0x8b, 0xf7 } };
				void* pFactory = nullptr;
				if ( SUCCEEDED( pCreateDXGIFactory1( IID_IDXGIFactory1, (void**)&pFactory ) ) && pFactory != nullptr )
				{
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

					using EnumAdapters1_t = HRESULT (__stdcall*)( void*, UINT, void** );
					using GetDesc1_t = HRESULT (__stdcall*)( void*, DXGI_ADAPTER_DESC1* );
					using Release_t = ULONG (__stdcall*)( void* );

					void** vtable = *(void***)pFactory;
					auto pEnumAdapters1 = (EnumAdapters1_t)vtable[7];

					for ( UINT adapterIndex = 0; adapterIndex < MAX_GPU_ADAPTERS; adapterIndex++ )
					{
						void* pAdapter = nullptr;
						HRESULT hr = pEnumAdapters1( pFactory, adapterIndex, &pAdapter );
						if ( FAILED( hr ) || pAdapter == nullptr )
							break;

						void** adapterVtable = *(void***)pAdapter;
						auto pGetDesc1 = (GetDesc1_t)adapterVtable[10];
						auto pRelease  = (Release_t)adapterVtable[2];

						DXGI_ADAPTER_DESC1 desc = {};
						if ( SUCCEEDED( pGetDesc1( pAdapter, &desc ) ) )
						{
							GPUAdapter& gpu = out.adapters[out.adapterCount++];
							wcscpy_s( gpu.name, desc.Description );
							gpu.vramMB    = desc.DedicatedVideoMemory / (1024 * 1024);
							gpu.sharedMB  = desc.SharedSystemMemory / (1024 * 1024);
							gpu.isIntegrated = ClassifyGpuAsIntegrated( desc.Description, desc.VendorId );

							// Intel iGPUs sometimes report 0 shared memory. Backfill from system RAM.
							if ( gpu.isIntegrated && gpu.sharedMB == 0 )
							{
								MEMORYSTATUSEX ms = { sizeof(ms) };
								if ( GlobalMemoryStatusEx( &ms ) )
									gpu.sharedMB = ms.ullTotalPhys / (1024 * 1024);
							}
						}
						pRelease( pAdapter );
					}

					auto pReleaseFactory = (Release_t)vtable[2];
					pReleaseFactory( pFactory );
				}
			}
			FreeLibrary( hDxgi );
		}

		// ----------------------------------------------------------------
		// Layer 2: Registry scan of the Display Class GUID.
		// This enumerates *every* installed display adapter driver,
		// including Optimus dGPUs that are hidden from DXGI/GDI.
		// ----------------------------------------------------------------
		{
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
					if ( RegOpenKeyExW( hKey, subkeyName, 0, KEY_READ, &hSubKey ) != ERROR_SUCCESS )
						continue;

					WCHAR driverDesc[256] = {};
					DWORD size = sizeof(driverDesc);
					bool hasDesc = (RegQueryValueExW( hSubKey, L"DriverDesc", nullptr, nullptr, (LPBYTE)driverDesc, &size ) == ERROR_SUCCESS);

					// Parse vendor from MatchingDeviceId (PCI\VEN_xxxx&DEV_xxxx...)
					uint32_t vendorId = 0;
					WCHAR matchId[256] = {};
					size = sizeof(matchId);
					if ( RegQueryValueExW( hSubKey, L"MatchingDeviceId", nullptr, nullptr, (LPBYTE)matchId, &size ) == ERROR_SUCCESS )
					{
						vendorId = ParseVendorIdFromPciString( matchId );
					}

					// Try to read VRAM from HardwareInformation.qwMemorySize (binary QWORD)
					uint64_t regVramMB = 0;
					DWORD qwType = 0;
					ULONGLONG qwMem = 0;
					DWORD qwSize = sizeof(qwMem);
					if ( RegQueryValueExW( hSubKey, L"HardwareInformation.qwMemorySize", nullptr, &qwType, (LPBYTE)&qwMem, &qwSize ) == ERROR_SUCCESS )
					{
						if ( qwType == REG_BINARY && qwSize == sizeof(ULONGLONG) )
							regVramMB = qwMem / (1024 * 1024);
						else if ( qwType == REG_QWORD )
							regVramMB = qwMem / (1024 * 1024);
					}

					// If we have a name and it is not already known, add it.
					if ( hasDesc && driverDesc[0] != L'\0' &&
					     out.adapterCount < MAX_GPU_ADAPTERS &&
					     !IsAdapterNameKnown( out, driverDesc ) )
					{
						GPUAdapter& gpu = out.adapters[out.adapterCount++];
						wcscpy_s( gpu.name, driverDesc );
						gpu.vramMB   = regVramMB;
						gpu.sharedMB = 0;
						gpu.isIntegrated = ClassifyGpuAsIntegrated( driverDesc, vendorId );
					}

					RegCloseKey( hSubKey );
				}
				RegCloseKey( hKey );
			}
		}

		// ----------------------------------------------------------------
		// Layer 3: EnumDisplayDevices (legacy fallback)
		// ----------------------------------------------------------------
		{
			DISPLAY_DEVICEW dd = { sizeof(dd) };
			for ( DWORD deviceIndex = 0; deviceIndex < MAX_GPU_ADAPTERS; deviceIndex++ )
			{
				if ( !EnumDisplayDevicesW( nullptr, deviceIndex, &dd, 0 ) )
					break;
				if ( dd.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER )
					continue;
				if ( out.adapterCount >= MAX_GPU_ADAPTERS )
					break;
				if ( IsAdapterNameKnown( out, dd.DeviceString ) )
					continue;

				GPUAdapter& gpu = out.adapters[out.adapterCount++];
				wcscpy_s( gpu.name, dd.DeviceString );
				gpu.vramMB   = 0;
				gpu.sharedMB = 0;
				gpu.isIntegrated = ClassifyGpuAsIntegrated( dd.DeviceString, 0 );
			}
		}

		// ----------------------------------------------------------------
		// Driver date: match against any adapter name
		// ----------------------------------------------------------------
		if ( out.adapterCount > 0 )
		{
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
							bool matched = false;
							for ( uint32_t i = 0; i < out.adapterCount; i++ )
							{
								if ( wcsstr( out.adapters[i].name, driverDesc ) != nullptr ||
								     wcsstr( driverDesc, out.adapters[i].name ) != nullptr )
								{
									matched = true;
									break;
								}
							}
							if ( matched )
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
