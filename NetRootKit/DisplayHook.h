#pragma once

typedef int                int32_t;
typedef unsigned int       uint32_t;
typedef long long          int64_t;
typedef unsigned long long uint64_t;

namespace DisplayHook
{
	typedef struct _protect_sprite_content
	{
		ULONG pid;
		uint32_t value;
		uint64_t window_handle;
	} protect_sprite_content, * pprotect_sprite_content;

	NTSTATUS DisableWindowCaptureprotect(pprotect_sprite_content req);
}