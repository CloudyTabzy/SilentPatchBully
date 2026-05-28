#pragma once

#include <windows.h>
#include <cstdint>

namespace CrashReporter
{
	struct OSInfo
	{
		wchar_t edition[128];
		uint32_t major;
		uint32_t minor;
		uint32_t build;
		bool isWine;
	};

	struct MemoryInfo
	{
		uint64_t totalPhysicalMB;
		uint64_t availPhysicalMB;
		uint64_t processWorkingSetMB;
		uint64_t processVirtualMB;
		bool largeAddressAware;
	};

	struct GPUInfo
	{
		wchar_t adapterName[128];
		uint64_t vramMB;
		wchar_t driverDate[32];
	};

	struct ProcessInfo
	{
		uint32_t pid;
		uint32_t runtimeSeconds;
		wchar_t exePath[MAX_PATH];
	};

	void CollectOSInfo( OSInfo& out );
	void CollectMemoryInfo( MemoryInfo& out, bool checkLAA );
	void CollectGPUInfo( GPUInfo& out );
	void CollectProcessInfo( ProcessInfo& out );
	bool IsLargeAddressAware( HMODULE hModule );
}
