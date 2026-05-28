#pragma once

#include <windows.h>

namespace CrashReporter
{
	// Install the VEH crash reporter. Call once during DLL init.
	void Install( HINSTANCE hModule );

	// Enable/disable crash reporting (checked at crash time, not during gameplay)
	void SetEnabled( bool enable );
	bool IsEnabled();

	// Set the game state string for crash context (e.g. "Chapter 2 - Loading").
	// Call from hook points if you want richer context. Safe to call from any thread.
	void SetGameState( const char* state );
}
