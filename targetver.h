#pragma once

// Windows 10 1903+ is required for webauthn.dll (Windows Hello / FIDO platform API)
#include <WinSDKVer.h>
#define _WIN32_WINNT 0x0A00
#include <SDKDDKVer.h>
