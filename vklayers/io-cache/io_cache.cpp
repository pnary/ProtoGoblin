#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <strings.h>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <memory>
#include <limits>

#include "io_cache.h"

// Real libc function pointers
typedef int (*pfn_open)(const char*, int, ...);
typedef int (*pfn_open64)(const char*, int, ...);
typedef ssize_t (*pfn_pread64)(int, void*, size_t, off64_t);
typedef ssize_t (*pfn_read)(int, void*, size_t);
typedef int (*pfn_close)(int);

static pfn_open g_real_open = nullptr;
static pfn_open64 g_real_open64 = nullptr;
static pfn_pread64 g_real_pread64 = nullptr;
static pfn_read g_real_read = nullptr;
static pfn_close g_real_close = nullptr;

static std::once_flag g_init_once;

// Atomic telemetry counters
static std::atomic<uint64_t> g_ioReadsTotal{0};
static std::atomic<uint64_t> g_ioCachedHits{0};
static std::atomic<uint64_t> g_ioBytesReadTotal{0};
static std::atomic<uint64_t> g_ioBytesSaved{0};
static std::atomic<uint64_t> g_ioTrackedFilesCount{0};

// Cache constants: 512 KB read-ahead chunk, cache reads up to 128 KB
static constexpr size_t CACHE_CHUNK_SIZE = 512 * 1024;
static constexpr size_t MAX_CACHABLE_READ_SIZE = 128 * 1024;

struct FileCacheSlot {
    off64_t window_start = -1;
    size_t window_size = 0;
    std::vector<uint8_t> buffer;
    std::mutex slot_lock;
    struct stat fingerprint{};
    bool fingerprint_valid = false;
};

static std::mutex g_trackedLock;
static std::unordered_map<int, std::shared_ptr<FileCacheSlot>> g_trackedFiles;

static bool IsIoCacheEnabled() {
    static const bool enabled = [] {
        const char* env = getenv("PROTOGOBLIN_IO_CACHE");
        return env && (env[0] == '1' || env[0] == 't' || env[0] == 'T' || env[0] == 'y' || env[0] == 'Y');
    }();
    return enabled;
}

static bool ShouldTrackFile(const char* path, int flags) {
    if (!path) return false;
    // Only track read-only opens
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & (O_DIRECT | O_PATH))) return false;

    // Check extensions commonly associated with massive streaming chunk reads
    const char* ext = strrchr(path, '.');
    if (!ext) return false;

    static const char* s_extensions[] = {
        ".pak", ".bundle", ".dat", ".cas", ".vpk", ".cpk", ".bin",
        ".toc", ".bank", ".pck", ".assets", ".resource", ".fsb"
    };

    for (const char* target_ext : s_extensions) {
        if (strcasecmp(ext, target_ext) == 0) {
            return true;
        }
    }
    return false;
}

static void InitRealSymbols() {
    g_real_open = (pfn_open)dlsym(RTLD_NEXT, "open");
    g_real_open64 = (pfn_open64)dlsym(RTLD_NEXT, "open64");
    g_real_pread64 = (pfn_pread64)dlsym(RTLD_NEXT, "pread64");
    g_real_read = (pfn_read)dlsym(RTLD_NEXT, "read");
    g_real_close = (pfn_close)dlsym(RTLD_NEXT, "close");

    std::atexit(protogoblin_io_cache_flush_stats);
}

static void EnsureInitialized() {
    std::call_once(g_init_once, InitRealSymbols);
}

extern "C" void protogoblin_io_cache_flush_stats(void) {
    static std::atomic<bool> s_flushed{false};
    if (s_flushed.exchange(true)) return;

    const char* session_dir = getenv("PROTOGOBLIN_SESSION_DIR");
    if (!session_dir) return;

    char out_path[1024];
    snprintf(out_path, sizeof(out_path), "%s/protogoblin_io_stats.json", session_dir);

    FILE* fp = fopen(out_path, "w");
    if (!fp) return;

    uint64_t reads_total = g_ioReadsTotal.load(std::memory_order_relaxed);
    uint64_t cached_hits = g_ioCachedHits.load(std::memory_order_relaxed);
    uint64_t bytes_read = g_ioBytesReadTotal.load(std::memory_order_relaxed);
    uint64_t bytes_saved = g_ioBytesSaved.load(std::memory_order_relaxed);
    uint64_t tracked_files = g_ioTrackedFilesCount.load(std::memory_order_relaxed);

    double hit_rate = reads_total > 0 ? ((double)cached_hits * 100.0 / (double)reads_total) : 0.0;
    // Estimated latency savings assuming ~0.015ms per avoided synchronous kernel crossing
    double latency_saved_ms = (double)cached_hits * 0.015;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"io_cache_active\": %s,\n", IsIoCacheEnabled() ? "true" : "false");
    fprintf(fp, "  \"tracked_archives_count\": %llu,\n", (unsigned long long)tracked_files);
    fprintf(fp, "  \"reads_total\": %llu,\n", (unsigned long long)reads_total);
    fprintf(fp, "  \"reads_cached_hits\": %llu,\n", (unsigned long long)cached_hits);
    fprintf(fp, "  \"hit_rate_pct\": %.2f,\n", hit_rate);
    fprintf(fp, "  \"bytes_read_total\": %llu,\n", (unsigned long long)bytes_read);
    fprintf(fp, "  \"bytes_cached_saved\": %llu,\n", (unsigned long long)bytes_saved);
    fprintf(fp, "  \"estimated_latency_saved_ms\": %.2f\n", latency_saved_ms);
    fprintf(fp, "}\n");
    fclose(fp);
}

// POSIX interceptors
extern "C" int open(const char* pathname, int flags, ...) {
    EnsureInitialized();
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    int fd = g_real_open ? g_real_open(pathname, flags, mode) : -1;
    if (fd >= 0 && ShouldTrackFile(pathname, flags)) {
        std::lock_guard<std::mutex> lock(g_trackedLock);
        if (g_trackedFiles.find(fd) == g_trackedFiles.end()) {
            g_trackedFiles[fd] = std::make_shared<FileCacheSlot>();
            g_ioTrackedFilesCount.fetch_add(1, std::memory_order_relaxed);
        }
    }
    return fd;
}

extern "C" int open64(const char* pathname, int flags, ...) {
    EnsureInitialized();
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    int fd = g_real_open64 ? g_real_open64(pathname, flags, mode) : (g_real_open ? g_real_open(pathname, flags, mode) : -1);
    if (fd >= 0 && ShouldTrackFile(pathname, flags)) {
        std::lock_guard<std::mutex> lock(g_trackedLock);
        if (g_trackedFiles.find(fd) == g_trackedFiles.end()) {
            g_trackedFiles[fd] = std::make_shared<FileCacheSlot>();
            g_ioTrackedFilesCount.fetch_add(1, std::memory_order_relaxed);
        }
    }
    return fd;
}

extern "C" ssize_t pread64(int fd, void* buf, size_t count, off64_t offset) {
    EnsureInitialized();
    if (!g_real_pread64) return -1;

    std::shared_ptr<FileCacheSlot> slot;
    std::unique_lock<std::mutex> slot_lock;
    {
        std::lock_guard<std::mutex> lock(g_trackedLock);
        auto it = g_trackedFiles.find(fd);
        if (it != g_trackedFiles.end()) {
            slot = it->second;
            slot_lock = std::unique_lock<std::mutex>(slot->slot_lock);
        }
    }

    if (!slot) {
        return g_real_pread64(fd, buf, count, offset);
    }

    auto read_real = [&]() {
        ssize_t result = g_real_pread64(fd, buf, count, offset);
        if (result > 0) g_ioBytesReadTotal.fetch_add((uint64_t)result, std::memory_order_relaxed);
        return result;
    };
    g_ioReadsTotal.fetch_add(1, std::memory_order_relaxed);
    if (!IsIoCacheEnabled() || count > MAX_CACHABLE_READ_SIZE || count == 0 || !buf || offset < 0 ||
        offset > std::numeric_limits<off64_t>::max() - (off64_t)count) {
        return read_real();
    }

    // A read-only handle does not imply an immutable file. Invalidate cached
    // bytes when another handle changes the archive (including same-size writes).
    struct stat current{};
    if (fstat(fd, &current) != 0 || !S_ISREG(current.st_mode)) {
        return read_real();
    }
    const auto& previous = slot->fingerprint;
    if (!slot->fingerprint_valid || current.st_size != previous.st_size ||
        current.st_mtim.tv_sec != previous.st_mtim.tv_sec || current.st_mtim.tv_nsec != previous.st_mtim.tv_nsec ||
        current.st_ctim.tv_sec != previous.st_ctim.tv_sec || current.st_ctim.tv_nsec != previous.st_ctim.tv_nsec) {
        slot->window_start = -1;
        slot->window_size = 0;
    }
    slot->fingerprint = current;
    slot->fingerprint_valid = true;

    // 1. Cache hit check
    if (slot->window_start >= 0 &&
        offset >= slot->window_start &&
        (offset + (off64_t)count) <= (slot->window_start + (off64_t)slot->window_size)) {
        size_t rel_offset = (size_t)(offset - slot->window_start);
        std::memcpy(buf, slot->buffer.data() + rel_offset, count);
        g_ioCachedHits.fetch_add(1, std::memory_order_relaxed);
        g_ioBytesSaved.fetch_add(count, std::memory_order_relaxed);
        g_ioBytesReadTotal.fetch_add(count, std::memory_order_relaxed);
        return (ssize_t)count;
    }

    // 2. Cache miss: Read-ahead aligned chunk
    off64_t chunk_start = offset & ~((off64_t)(CACHE_CHUNK_SIZE - 1));
    if (slot->buffer.size() < CACHE_CHUNK_SIZE) {
        slot->buffer.resize(CACHE_CHUNK_SIZE);
    }

    ssize_t bytes_fetched = g_real_pread64(fd, slot->buffer.data(), CACHE_CHUNK_SIZE, chunk_start);
    if (bytes_fetched <= 0) {
        slot->window_start = -1;
        slot->window_size = 0;
        return read_real();
    }

    slot->window_start = chunk_start;
    slot->window_size = (size_t)bytes_fetched;

    // Verify if requested slice fits in the fetched chunk
    if (offset >= slot->window_start &&
        (offset + (off64_t)count) <= (slot->window_start + (off64_t)slot->window_size)) {
        size_t rel_offset = (size_t)(offset - slot->window_start);
        std::memcpy(buf, slot->buffer.data() + rel_offset, count);
        g_ioBytesReadTotal.fetch_add(count, std::memory_order_relaxed);
        return (ssize_t)count;
    }
    // A cache window boundary is not EOF. Let libc satisfy the entire request.

    return read_real();
}

extern "C" ssize_t read(int fd, void* buf, size_t count) {
    EnsureInitialized();
    if (!g_real_read) return -1;
    return g_real_read(fd, buf, count);
}

extern "C" int close(int fd) {
    EnsureInitialized();
    {
        std::lock_guard<std::mutex> lock(g_trackedLock);
        auto it = g_trackedFiles.find(fd);
        if (it != g_trackedFiles.end()) {
            auto slot = it->second;
            std::lock_guard<std::mutex> slot_lock(slot->slot_lock);
            g_trackedFiles.erase(it);
            return g_real_close ? g_real_close(fd) : -1;
        }
    }
    return g_real_close ? g_real_close(fd) : -1;
}

__attribute__((constructor))
static void protogoblin_io_cache_ctor() {
    EnsureInitialized();
}

__attribute__((destructor))
static void protogoblin_io_cache_dtor() {
    protogoblin_io_cache_flush_stats();
}
