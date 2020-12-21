#pragma once
#include <cstdint>
#include "size_assert.hpp"

namespace Mt {
	class MtMemoryStream {
	public:
		uint64_t mFlags;
		uint8_t* mBuffer;
		uint64_t mReadIndex;
		uint64_t mTotalSize;
		uint64_t field_28;
		uint64_t field_30;

		virtual ~MtMemoryStream() {};
	};
	assert_size(MtMemoryStream, 0x38);

	class cRemoteCall {
	public:
		using remote_call_create_t = void* (__fastcall*)(MtMemoryStream*);
	};
}