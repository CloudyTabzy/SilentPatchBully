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

	struct GPUAdapter
	{
		wchar_t name[128];
		uint64_t vramMB;
		uint64_t sharedMB;
		bool isIntegrated;
	};

	static constexpr size_t MAX_GPU_ADAPTERS = 4;

	struct GPUInfo
	{
		GPUAdapter adapters[MAX_GPU_ADAPTERS];
		uint32_t adapterCount;
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
