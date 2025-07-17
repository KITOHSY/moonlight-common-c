#pragma once

#include <stdint.h>

#pragma pack(push, 1)

typedef struct _NV_FILE_HEADER {
    uint32_t size; // Size of packet (excluding this field) - Big Endian
    uint32_t magic; // Packet type - Little Endian
} NV_FILE_HEADER, *PNV_FILE_HEADER;

typedef struct _SS_FILE_PACKET {
    NV_FILE_HEADER header;
    char* filePath;
} SS_FILE_PACKET, *PSS_FILE_PACKET;

#pragma pack(pop)
