#pragma once
#include <windows.h>
#include <sstream>
#include <vector>
#include "SigScan.hpp"

// Hahaha, this is kinda dumb, but I can't link to loader.dll directly (and it only exports mangled C++ names).
// To use the loader's logger, we manually sigscan for the "_log" function and call that C impl.
namespace loader {
	using log_t = void(__fastcall*)(int l, const char* s);
	static log_t fpLog = nullptr;

	enum class LogLevel : int {
		DEBUG = 0,
		INFO = 1,
		WARN = 2,
		ERR = 3,
	};

	void InitLogger() {
		static uint64_t image_base = (uint64_t)LoadLibraryA("loader.dll");
		uint64_t log_addr = SigScan::Scan(image_base, "48 89 5C 24 08 48 89 74 24 18 48 89 7C 24 20 55 41 54 41 55 41 56 41 57 48 8D 6C 24 90 48 81 EC 70 01 00 00");
		fpLog =  reinterpret_cast<log_t>(log_addr);
	}

	void log(LogLevel level, const char* str) {
		if (fpLog != nullptr) {
			fpLog((int)level, str);
		}
	}
}