#pragma once

#include "order_book.h"
#include <cstdint>

namespace hft {

struct MarketDataMessage {
    uint64_t sequenceNumber;
    uint64_t timestamp;
    uint64_t price;
    uint64_t quantity;
    uint32_t msgType;
    uint32_t flags;
    char symbol[32];
};

// FL010 target: seq_cst atomics where acquire/release suffices on x86-64 TSO.
class FeedHandler {
public:
    void onMessage(const MarketDataMessage &msg);
    uint64_t lastSequence() const;
    void spinAwaitReady(const std::atomic<bool> &readyFlag_);
    void spinAwaitReadyPaused(const std::atomic<bool> &readyFlag_);

private:
    OrderBook *book_ = nullptr;
    std::atomic<uint64_t> lastSeq_{0};
    std::atomic<bool> connected_{false};
};

// FL021 target: large stack frame from local arrays.
void decodeBatch(const char *buffer, size_t len, FeedHandler &handler);

} // namespace hft
