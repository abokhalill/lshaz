#include "feed_handler.h"
#include <cstring>

namespace hft {

// FL010 target: seq_cst where acquire/release suffices on x86-64 TSO.
void FeedHandler::onMessage(const MarketDataMessage &msg) {
    uint64_t expected = lastSeq_.load();
    if (msg.sequenceNumber <= expected)
        return;

    // seq_cst store where release would suffice.
    lastSeq_.store(msg.sequenceNumber);

    g_mdState.lastSeqNum.store(msg.sequenceNumber);
    g_mdState.lastTimestamp.store(msg.timestamp);
    g_mdState.totalMessages++;

    if (book_) {
        OrderBookLevel level{};
        level.priceFixed = msg.price;
        level.quantity = msg.quantity;
        level.sequenceNumber = msg.sequenceNumber;
        level.flags = msg.flags;
        std::memcpy(level.symbol, msg.symbol, sizeof(level.symbol));
        book_->addLevel(level);
    }
}

uint64_t FeedHandler::lastSequence() const {
    return lastSeq_.load();
}

// FL021 target: large stack frame from local decode buffers.
void decodeBatch(const char *buffer, size_t len, FeedHandler &handler) {
    MarketDataMessage decoded[128];
    char scratchpad[4096];

    size_t offset = 0;
    size_t count = 0;

    while (offset + sizeof(MarketDataMessage) <= len &&
           count < 128) {
        std::memcpy(&decoded[count], buffer + offset,
                     sizeof(MarketDataMessage));
        offset += sizeof(MarketDataMessage);
        ++count;
    }

    for (size_t i = 0; i < count; ++i) {
        std::memcpy(scratchpad, decoded[i].symbol,
                     sizeof(decoded[i].symbol));
        handler.onMessage(decoded[i]);
    }
}

// FL013 target: tight spin on an atomic with no pause — every
// invalidation of readyFlag_'s line costs a memory-order machine clear.
void FeedHandler::spinAwaitReady(const std::atomic<bool> &readyFlag_) {
    while (!readyFlag_.load(std::memory_order_acquire)) {
    }
}

// Control: identical spin with the pause hint — must NOT fire.
void FeedHandler::spinAwaitReadyPaused(const std::atomic<bool> &readyFlag_) {
    while (!readyFlag_.load(std::memory_order_acquire)) {
        __builtin_ia32_pause();
    }
}

} // namespace hft
