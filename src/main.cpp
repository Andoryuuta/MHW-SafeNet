#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <set>
#include "spdlog/spdlog.h"
#include "strackeror_logger.h"
#include "MinHook.h"
#include "SigScan.hpp"
#include "Mt.hpp"

const static std::set<uint32_t> SafeRpcClasses = {
	0x39EC3064, // nNetwork::RpcNetSystem_AnsDetour
	0x5BE7381E, // nNetwork::RpcNetSystem_Config
	0x3DDC4535, // nNetwork::RpcNetSystem_Core
	0x49A5BB1F, // nNetwork::RpcNetSystem_Entry
	0x1266DC19, // nNetwork::RpcNetSystem_HealthCheck
	0x7934A6BF, // nNetwork::RpcNetSystem_Leave
	0x0CA2406D, // nNetwork::RpcNetSystem_LinkState
	0x18DFE36A, // nNetwork::RpcNetSystem_Match
	0x75B10DEF, // nNetwork::RpcNetSystem_RouteKey
	0x4E9E0DFC, // nNetwork::RpcNetSystem_RouteKeyAck
	0x6E07B730, // nNetwork::RpcNetSystem_Terminate
	0x3E926E9B, // nNetwork::RpcNetSystem_TryConnect

	0x43288400, // nNetwork::TagChecker
	0x4FAE7A0B, // nNetwork::TagChecker::RpcSyncAns
	0x5C34DFC5, // nNetwork::TagChecker::RpcSyncReq
};

Mt::cRemoteCall::remote_call_create_t OriginalRemoteCallCreate = nullptr;
void* __fastcall HookedRemoteCallCreate(Mt::MtMemoryStream* stream) {
	if (stream->mReadIndex != 0) {
		loader::log(loader::LogLevel::ERR, "stream->mReadIndex != 0 -- This shouldn't happen!\n");
		std::this_thread::sleep_for(std::chrono::minutes(5));
		return nullptr;
	}
	
	uint32_t class_hash = 0;
	if (stream->mTotalSize >= 4) {
		class_hash |= ((uint32_t)stream->mBuffer[0]) << 24;
		class_hash |= ((uint32_t)stream->mBuffer[1]) << 16;
		class_hash |= ((uint32_t)stream->mBuffer[2]) << 8;
		class_hash |= ((uint32_t)stream->mBuffer[3]) << 0;
	}

	if (SafeRpcClasses.find(class_hash) != SafeRpcClasses.end()) {
		return OriginalRemoteCallCreate(stream);
	}

	loader::log(loader::LogLevel::WARN, fmt::format("Received non-safe class for deserialization! Class hash: 0x{0:X}\n", class_hash).c_str());
	return nullptr;
}

DWORD WINAPI MyFunc(LPVOID lpvParam)
{
	loader::InitLogger();

	loader::log(loader::LogLevel::INFO, "MHW-SafeNet started\n");

	uint64_t image_base = (uint64_t)GetModuleHandle(NULL);
	uint64_t remote_call_ctor_addr = SigScan::Scan(image_base, "48 89 5c 24 10 56 48 81 ec 80 04 00 00 48 8b f1 48 8b d1");
	if (remote_call_ctor_addr == 0) {
		loader::log(loader::LogLevel::ERR, "Failed to get remote_call_ctor_addr\n");
		return 1;
	}
	
	if (MH_Initialize() != MH_OK) {
		loader::log(loader::LogLevel::ERR, "Failed to initialize Minhook\n");
		return 1;
	}

	if (MH_CreateHook(reinterpret_cast<LPVOID*>(remote_call_ctor_addr), reinterpret_cast<LPVOID*>(&HookedRemoteCallCreate), reinterpret_cast<LPVOID*>(&OriginalRemoteCallCreate)) != MH_OK)
	{
		loader::log(loader::LogLevel::ERR, "Failed to create hook\n");
		return 1;
	}

	if (MH_EnableHook(reinterpret_cast<LPVOID*>(remote_call_ctor_addr)) != MH_OK)
	{
		loader::log(loader::LogLevel::ERR, "Failed to enable hook\n");
		return 1;
	}

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		CreateThread(NULL, 0, MyFunc, 0, 0, NULL);
	}

	return TRUE;
}