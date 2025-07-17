#include "Limelight-internal.h"

static SOCKET fileSock = INVALID_SOCKET;

static unsigned char currentAesIv[16];
static bool initialized;
static bool encryptedControlStream;
static bool needsBatchedScroll;
static int batchedScrollDelta;
static PPLT_CRYPTO_CONTEXT cryptoContext;

static LINKED_BLOCKING_QUEUE packetQueue;
static LINKED_BLOCKING_QUEUE packetHolderFreeList;
static PLT_THREAD fileSendThread;
static PLT_MUTEX batchedFileMutex;

#define MAX_INPUT_PACKET_SIZE 128
#define FILE_STREAM_TIMEOUT_SEC 10
#define MAX_QUEUED_INPUT_PACKETS 150

#define PAYLOAD_SIZE(x) BE32((x)->packet.header.size)
#define PACKET_SIZE(x) (PAYLOAD_SIZE(x) + sizeof(uint32_t))

// Contains input stream packets
typedef struct _PACKET_HOLDER {
    LINKED_BLOCKING_QUEUE_ENTRY entry;
    uint32_t enetPacketFlags;
    uint8_t channelId;

    union {
        NV_FILE_HEADER header;
        SS_FILE_PACKET file;
    } packet;
} PACKET_HOLDER, *PPACKET_HOLDER;

// Initializes the file stream
int initializeFileStream(void) {
    memcpy(currentAesIv, StreamConfig.remoteInputAesIv, sizeof(currentAesIv));

    LbqInitializeLinkedBlockingQueue(&packetQueue, MAX_QUEUED_INPUT_PACKETS);
    LbqInitializeLinkedBlockingQueue(&packetHolderFreeList, MAX_QUEUED_INPUT_PACKETS);

    cryptoContext = PltCreateCryptoContext();
    encryptedControlStream = APP_VERSION_AT_LEAST(7, 1, 431);

    // FIXME: Unsure if this is exactly right, but it's probably good enough.
    //
    // GFE 3.13.1.30 is not using NVVHCI for mouse/keyboard (and is confirmed unaffected)
    // GFE 3.15.0.164 seems to be the first release using NVVHCI for mouse/keyboard
    //
    // Sunshine also uses SendInput() so it's not affected either.
    needsBatchedScroll = APP_VERSION_AT_LEAST(7, 1, 409) && !IS_SUNSHINE();
    batchedScrollDelta = 0;

    PltCreateMutex(&batchedFileMutex);

    return 0;
}


// Destroys and cleans up the file stream
void destroyFileStream(void) {
    PLINKED_BLOCKING_QUEUE_ENTRY entry, nextEntry;

    PltDestroyCryptoContext(cryptoContext);

    entry = LbqDestroyLinkedBlockingQueue(&packetQueue);

    while (entry != NULL) {
        nextEntry = entry->flink;

        // The entry is stored in the data buffer
        free(entry->data);

        entry = nextEntry;
    }

    entry = LbqDestroyLinkedBlockingQueue(&packetHolderFreeList);

    while (entry != NULL) {
        nextEntry = entry->flink;

        // The entry is stored in the data buffer
        free(entry->data);

        entry = nextEntry;
    }

    PltDeleteMutex(&batchedFileMutex);
}

static int encryptData(unsigned char* plaintext, int plaintextLen,
                       unsigned char* ciphertext, int* ciphertextLen) {
    // Starting in Gen 7, AES GCM is used for encryption
    if (AppVersionQuad[0] >= 7) {
        if (!PltEncryptMessage(cryptoContext, ALGORITHM_AES_GCM, 0,
                               (unsigned char*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
                               currentAesIv, sizeof(currentAesIv),
                               ciphertext, 16,
                               plaintext, plaintextLen,
                               &ciphertext[16], ciphertextLen)) {
            return -1;
        }

        // Increment the ciphertextLen to account for the tag
        *ciphertextLen += 16;
        return 0;
    }
    else {
        // PKCS7 padding may need to be added in-place, so we must copy this into a buffer
        // that can safely be modified.
        unsigned char paddedData[ROUND_TO_PKCS7_PADDED_LEN(MAX_INPUT_PACKET_SIZE)];

        memcpy(paddedData, plaintext, plaintextLen);

        // Prior to Gen 7, 128-bit AES CBC is used for encryption with each message padded
        // to the block size to ensure messages are not delayed within the cipher.
        return PltEncryptMessage(cryptoContext, ALGORITHM_AES_CBC, CIPHER_FLAG_PAD_TO_BLOCK_SIZE,
                                 (unsigned char*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
                                 currentAesIv, sizeof(currentAesIv),
                                 NULL, 0,
                                 paddedData, plaintextLen,
                                 ciphertext, ciphertextLen) ? 0 : -1;
    }
}

static void freePacketHolder(PPACKET_HOLDER holder) {
    LC_ASSERT(holder->packet.header.size != 0);

    // Place the packet holder back into the free list if it's a standard size entry
    if (PACKET_SIZE(holder) > (int)sizeof(*holder) || LbqOfferQueueItem(&packetHolderFreeList, holder, &holder->entry) != LBQ_SUCCESS) {
        free(holder);
    }
}

static PPACKET_HOLDER allocatePacketHolder(int extraLength) {
    PPACKET_HOLDER holder;
    int err;

    // If we're using an extended packet holder, we can't satisfy
    // this allocation from the packet holder free list.
    if (extraLength > 0) {
        // We over-allocate here a bit since we're always adding sizeof(*holder),
        // but this is on purpose. It allows us assume we have a full holder even
        // if packetLength < sizeof(*holder) and put this allocation into the free
        // list.
        return malloc(sizeof(*holder) + extraLength);
    }

    // Grab an entry from the free list (if available)
    err = LbqPollQueueElement(&packetHolderFreeList, (void**)&holder);
    if (err == LBQ_SUCCESS) {
        return holder;
    }
    else if (err == LBQ_INTERRUPTED) {
        // We're shutting down. Don't bother allocating.
        return NULL;
    }
    else {
        LC_ASSERT(err == LBQ_NO_ELEMENT);

        // Otherwise we'll have to allocate
        return malloc(sizeof(*holder));
    }
}

// File thread proc
static void fileSendThreadProc(void* context) {
    SOCK_RET err;
    PPACKET_HOLDER holder;

    while (!PltIsThreadInterrupted(&fileSendThread)) {
        // 인풋스트림에서는 패킷 큐에서 패킷 홀더를 가져온 후 패킷 타입에 맞게 분기
        // 하지만 파일스트림에서는 별도의 분기가 필요하지 않기 때문에
        // 

        // Encrypt and send the input packet
        if (!sendInputPacket(holder, LbqGetItemCount(&packetQueue) > 0)) {
            freePacketHolder(holder);
            return;
        }
    }
}


// Begin the file stream
int startFileStream(void) {
    int err;

    // After Gen 5, we send input on the control stream
    if (AppVersionQuad[0] < 5) {
        fileSock = connectTcpSocket(&RemoteAddr, AddrLen,
                                     30912, FILE_STREAM_TIMEOUT_SEC);
        if (fileSock == INVALID_SOCKET) {
            return LastSocketFail();
        }

        enableNoDelay(fileSock);
    }

    err = PltCreateThread("FileSend", fileSendThreadProc, NULL, &fileSendThread);
    if (err != 0) {
        if (fileSock != INVALID_SOCKET) {
            closeSocket(fileSock);
            fileSock = INVALID_SOCKET;
        }
        return err;
    }

    // Allow input packets to be queued now
    initialized = true;

    return err;
}

