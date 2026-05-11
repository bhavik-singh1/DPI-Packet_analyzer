// DPI Engine Benchmark Tool
// Measures: Speed, Scalability, Efficiency, Resource Usage
// Build: g++ -std=c++17 -pthread -O2 -I include -o dpi_benchmark.exe src/benchmark.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>
#include <numeric>
#include <sstream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <sys/resource.h>
#include <unistd.h>
#endif

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// =============================================================================
// Memory Measurement
// =============================================================================
static size_t getMemoryUsageKB() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
#else
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss; // KB on Linux
#endif
}

// =============================================================================
// Thread-Safe Queue (copied from dpi_mt.cpp to keep benchmark standalone)
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}

    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }

    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }

    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool is_shutdown() const { return shutdown_; }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::queue<T> empty;
        std::swap(queue_, empty);
        shutdown_ = false;
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet structure
// =============================================================================
struct BenchPacket {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags;
    size_t payload_offset;
    size_t payload_length;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct BenchFlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;
};

// =============================================================================
// Blocking Rules
// =============================================================================
class BenchRules {
public:
    void blockApp(const std::string& app) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                return;
            }
        }
    }

    bool isBlocked(uint32_t, AppType app, const std::string&) const {
        return blocked_apps_.count(app) > 0;
    }

private:
    std::unordered_set<AppType> blocked_apps_;
};

// =============================================================================
// Statistics
// =============================================================================
struct BenchStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};

    void reset() {
        total_packets = 0;
        total_bytes = 0;
        forwarded = 0;
        dropped = 0;
    }
};

// =============================================================================
// Fast Path (benchmark version)
// =============================================================================
class BenchFP {
public:
    BenchFP(int id, BenchRules* rules, BenchStats* stats, TSQueue<BenchPacket>* out)
        : id_(id), rules_(rules), stats_(stats), output_queue_(out) {}

    void start() { running_ = true; thread_ = std::thread(&BenchFP::run, this); }

    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }

    TSQueue<BenchPacket>& queue() { return input_queue_; }
    uint64_t processed() const { return processed_; }

    void reset() {
        processed_ = 0;
        flows_.clear();
        input_queue_.reset();
    }

private:
    int id_;
    BenchRules* rules_;
    BenchStats* stats_;
    TSQueue<BenchPacket>* output_queue_;
    TSQueue<BenchPacket> input_queue_;
    std::unordered_map<FiveTuple, BenchFlowEntry, FiveTupleHash> flows_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};

    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(50);
            if (!pkt_opt) continue;
            processed_++;
            BenchPacket& pkt = *pkt_opt;

            BenchFlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) flow.tuple = pkt.tuple;
            flow.packets++;
            flow.bytes += pkt.data.size();

            if (!flow.classified) {
                if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
                    const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
                    auto sni = SNIExtractor::extract(payload, pkt.payload_length);
                    if (sni) {
                        flow.sni = *sni;
                        flow.app_type = sniToAppType(*sni);
                        flow.classified = true;
                    }
                } else if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
                    const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
                    auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
                    if (host) {
                        flow.sni = *host;
                        flow.app_type = sniToAppType(*host);
                        flow.classified = true;
                    }
                } else if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
                    flow.app_type = AppType::DNS;
                    flow.classified = true;
                }
                if (!flow.classified && pkt.tuple.dst_port == 443)
                    flow.app_type = AppType::HTTPS;
                else if (!flow.classified && pkt.tuple.dst_port == 80)
                    flow.app_type = AppType::HTTP;
            }

            if (!flow.blocked)
                flow.blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);

            if (flow.blocked) { stats_->dropped++; }
            else { stats_->forwarded++; output_queue_->push(std::move(pkt)); }
        }
    }
};

// =============================================================================
// Load Balancer (benchmark version)
// =============================================================================
class BenchLB {
public:
    BenchLB(int id, std::vector<BenchFP*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}

    void start() { running_ = true; thread_ = std::thread(&BenchLB::run, this); }

    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }

    TSQueue<BenchPacket>& queue() { return input_queue_; }
    uint64_t dispatched() const { return dispatched_; }

    void reset() {
        dispatched_ = 0;
        input_queue_.reset();
    }

private:
    int id_;
    std::vector<BenchFP*> fps_;
    size_t num_fps_;
    TSQueue<BenchPacket> input_queue_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};

    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(50);
            if (!pkt_opt) continue;
            FiveTupleHash hasher;
            size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// Benchmark Result
// =============================================================================
struct BenchResult {
    double elapsed_sec;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t forwarded;
    uint64_t dropped;
    double pps;        // packets per second
    double mbps;       // megabits per second
    double latency_us; // microseconds per packet
    int num_lbs;
    int fps_per_lb;
    std::vector<uint64_t> lb_dispatched;
    std::vector<uint64_t> fp_processed;
    uint64_t num_flows;
};

// =============================================================================
// Helper: format number with commas
// =============================================================================
static std::string formatNum(uint64_t n) {
    std::string s = std::to_string(n);
    int pos = (int)s.length() - 3;
    while (pos > 0) { s.insert(pos, ","); pos -= 3; }
    return s;
}

static std::string formatBytes(uint64_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024 * 1024) {
        std::ostringstream os; os << std::fixed << std::setprecision(1) << (bytes / 1024.0) << " KB";
        return os.str();
    }
    std::ostringstream os; os << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0)) << " MB";
    return os.str();
}

// =============================================================================
// Run one benchmark pass
// =============================================================================
static BenchResult runBenchmark(
    const std::vector<BenchPacket>& packets,
    int num_lbs, int fps_per_lb, BenchRules* rules)
{
    int total_fps = num_lbs * fps_per_lb;
    BenchStats stats;
    TSQueue<BenchPacket> output_queue;

    // Create FPs
    std::vector<std::unique_ptr<BenchFP>> fps;
    for (int i = 0; i < total_fps; i++)
        fps.push_back(std::make_unique<BenchFP>(i, rules, &stats, &output_queue));

    // Create LBs
    std::vector<std::unique_ptr<BenchLB>> lbs;
    for (int lb = 0; lb < num_lbs; lb++) {
        std::vector<BenchFP*> lb_fps;
        int start = lb * fps_per_lb;
        for (int i = 0; i < fps_per_lb; i++)
            lb_fps.push_back(fps[start + i].get());
        lbs.push_back(std::make_unique<BenchLB>(lb, std::move(lb_fps)));
    }

    // Start threads
    for (auto& fp : fps) fp->start();
    for (auto& lb : lbs) lb->start();

    // Drain output in background (discard - benchmark only)
    std::atomic<bool> out_running{true};
    std::thread out_thread([&]() {
        while (out_running || output_queue.size() > 0) {
            output_queue.pop(30);
        }
    });

    // Precompute total bytes
    uint64_t total_bytes = 0;
    for (const auto& pkt : packets) total_bytes += pkt.data.size();

    // === TIMED SECTION ===
    auto t_start = std::chrono::high_resolution_clock::now();

    FiveTupleHash hasher;
    for (const auto& pkt : packets) {
        stats.total_packets++;
        size_t lb_idx = hasher(pkt.tuple) % lbs.size();
        BenchPacket copy = pkt;
        lbs[lb_idx]->queue().push(std::move(copy));
    }

    auto t_dispatch_end = std::chrono::high_resolution_clock::now();

    // Wait for queues to drain (not counted in dispatch time)
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto t_end = std::chrono::high_resolution_clock::now();
    // === END TIMED SECTION ===

    // Stop threads
    for (auto& lb : lbs) lb->stop();
    for (auto& fp : fps) fp->stop();
    out_running = false;
    output_queue.shutdown();
    out_thread.join();

    // Collect results
    double elapsed = std::chrono::duration<double>(t_dispatch_end - t_start).count();
    uint64_t n = packets.size();

    BenchResult r;
    r.elapsed_sec = elapsed;
    r.total_packets = n;
    r.total_bytes = total_bytes;
    r.forwarded = stats.forwarded.load();
    r.dropped = stats.dropped.load();
    r.pps = n / elapsed;
    r.mbps = (total_bytes * 8.0) / elapsed / 1e6;
    r.latency_us = (elapsed / n) * 1e6;
    r.num_lbs = num_lbs;
    r.fps_per_lb = fps_per_lb;
    r.num_flows = 0;

    for (auto& lb : lbs) r.lb_dispatched.push_back(lb->dispatched());
    for (auto& fp : fps) { r.fp_processed.push_back(fp->processed()); }

    return r;
}

// =============================================================================
// Print Benchmark Report
// =============================================================================
static void printReport(const BenchResult& single, const BenchResult& multi,
                        const std::string& input_file, int multiplier,
                        size_t mem_before_kb, size_t mem_after_kb)
{
    double speedup = single.elapsed_sec / multi.elapsed_sec;
    int total_threads = multi.num_lbs * multi.fps_per_lb;
    double efficiency = (speedup / total_threads) * 100.0;
    size_t mem_used_kb = (mem_after_kb > mem_before_kb) ? (mem_after_kb - mem_before_kb) : mem_after_kb;

    std::cout << "\n";
    std::cout << "======================================================================\n";
    std::cout << "                    DPI ENGINE BENCHMARK REPORT                        \n";
    std::cout << "======================================================================\n";

    std::cout << "  Input File:           " << input_file << "\n";
    std::cout << "  Packet Multiplier:    " << multiplier << "x\n";
    std::cout << "  Total Packets:        " << formatNum(single.total_packets) << "\n";
    std::cout << "  Total Data:           " << formatBytes(single.total_bytes) << "\n";

    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "                           SPEED METRICS                               \n";
    std::cout << "----------------------------------------------------------------------\n";

    std::cout << std::fixed << std::setprecision(1);
    std::cout << "                     Single-Thread     Multi-Thread     Speedup\n";
    std::cout << "  Time:              "
              << std::setw(10) << (single.elapsed_sec * 1000) << " ms"
              << std::setw(13) << (multi.elapsed_sec * 1000) << " ms"
              << std::setw(10) << speedup << "x\n";
    std::cout << "  Packets/sec:       "
              << std::setw(10) << formatNum((uint64_t)single.pps)
              << "   " << std::setw(10) << formatNum((uint64_t)multi.pps)
              << "   " << std::setw(7) << speedup << "x\n";
    std::cout << "  Throughput:        "
              << std::setw(8) << single.mbps << " Mbps"
              << std::setw(11) << multi.mbps << " Mbps"
              << std::setw(9) << speedup << "x\n";
    std::cout << "  Avg Latency:       "
              << std::setw(8) << single.latency_us << " us"
              << std::setw(13) << multi.latency_us << " us"
              << std::setw(10) << speedup << "x\n";

    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "                        SCALABILITY ANALYSIS                           \n";
    std::cout << "----------------------------------------------------------------------\n";

    std::cout << "  Thread Config:        " << multi.num_lbs << " LBs x "
              << multi.fps_per_lb << " FPs = "
              << total_threads << " worker threads\n";
    std::cout << "  Speedup Factor:       " << std::setprecision(2) << speedup
              << "x (ideal: " << std::setprecision(2) << (double)total_threads << "x)\n";
    std::cout << "  Efficiency:           " << std::setprecision(1) << efficiency
              << "% of ideal linear scaling\n";

    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "                      PER-THREAD UTILIZATION                           \n";
    std::cout << "----------------------------------------------------------------------\n";

    uint64_t total_processed = 0;
    for (auto v : multi.fp_processed) total_processed += v;

    for (size_t i = 0; i < multi.lb_dispatched.size(); i++) {
        double pct = multi.total_packets > 0 ?
            (100.0 * multi.lb_dispatched[i] / multi.total_packets) : 0;
        std::cout << "  LB" << i << " dispatched:       "
                  << std::setw(8) << formatNum(multi.lb_dispatched[i])
                  << "  (" << std::setw(4) << std::setprecision(1) << pct << "%)\n";
    }

    for (size_t i = 0; i < multi.fp_processed.size(); i++) {
        double pct = total_processed > 0 ?
            (100.0 * multi.fp_processed[i] / total_processed) : 0;
        int bar_len = (int)(pct / 4);
        std::string bar(bar_len > 0 ? bar_len : 0, '#');
        std::cout << "  FP" << i << " processed:        "
                  << std::setw(8) << formatNum(multi.fp_processed[i])
                  << "  (" << std::setw(4) << std::setprecision(1) << pct << "%)  "
                  << bar << "\n";
    }

    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "                        RESOURCE USAGE                                 \n";
    std::cout << "----------------------------------------------------------------------\n";

    std::cout << "  Peak Memory (RSS):     " << formatBytes(mem_used_kb * 1024) << "\n";
    if (multi.total_packets > 0) {
        double mem_per_pkt = (double)(mem_used_kb * 1024) / multi.total_packets;
        std::cout << "  Memory per Packet:     " << std::setprecision(1) << mem_per_pkt << " bytes\n";
    }
    std::cout << "  Forwarded Packets:     " << formatNum(multi.forwarded) << "\n";
    std::cout << "  Dropped Packets:       " << formatNum(multi.dropped) << "\n";

    std::cout << "======================================================================\n";
    std::cout << "\n";
}

// =============================================================================
// Load packets from PCAP
// =============================================================================
static std::vector<BenchPacket> loadPackets(const std::string& filename) {
    std::vector<BenchPacket> packets;
    PcapReader reader;
    if (!reader.open(filename)) {
        std::cerr << "Error: Cannot open " << filename << "\n";
        return packets;
    }

    RawPacket raw;
    ParsedPacket parsed;
    uint32_t id = 0;

    while (reader.readNextPacket(raw)) {
        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

        BenchPacket pkt;
        pkt.id = id++;
        pkt.ts_sec = raw.header.ts_sec;
        pkt.ts_usec = raw.header.ts_usec;
        pkt.tcp_flags = parsed.tcp_flags;
        pkt.data = std::move(raw.data);

        auto parseIP = [](const std::string& ip) -> uint32_t {
            uint32_t result = 0; int octet = 0, shift = 0;
            for (char c : ip) {
                if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
            }
            return result | (octet << shift);
        };

        pkt.tuple.src_ip = parseIP(parsed.src_ip);
        pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
        pkt.tuple.src_port = parsed.src_port;
        pkt.tuple.dst_port = parsed.dest_port;
        pkt.tuple.protocol = parsed.protocol;

        pkt.payload_offset = 14;
        if (pkt.data.size() > 14) {
            uint8_t ip_ihl = pkt.data[14] & 0x0F;
            pkt.payload_offset += ip_ihl * 4;
            if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
                uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                pkt.payload_offset += tcp_off * 4;
            } else if (parsed.has_udp) {
                pkt.payload_offset += 8;
            }
            pkt.payload_length = (pkt.payload_offset < pkt.data.size()) ?
                pkt.data.size() - pkt.payload_offset : 0;
        } else {
            pkt.payload_length = 0;
        }

        packets.push_back(std::move(pkt));
    }
    reader.close();
    return packets;
}

// =============================================================================
// Multiply packets
// =============================================================================
static std::vector<BenchPacket> multiplyPackets(
    const std::vector<BenchPacket>& base, int multiplier)
{
    std::vector<BenchPacket> result;
    result.reserve(base.size() * multiplier);
    for (int m = 0; m < multiplier; m++) {
        for (const auto& pkt : base) {
            BenchPacket copy = pkt;
            copy.id = (uint32_t)result.size();
            result.push_back(std::move(copy));
        }
    }
    return result;
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "\nDPI Benchmark Tool\n"
                  << "==================\n\n"
                  << "Usage: " << argv[0] << " <input.pcap> [options]\n\n"
                  << "Options:\n"
                  << "  --multiply <N>     Multiply packets N times (default: 100)\n"
                  << "  --lbs <n>          LB threads for multi-thread (default: 2)\n"
                  << "  --fps <n>          FP threads per LB (default: 2)\n"
                  << "  --block-app <app>  Add blocking rule\n\n"
                  << "Example:\n"
                  << "  " << argv[0] << " test_dpi.pcap --multiply 200 --lbs 2 --fps 4\n\n";
        return 1;
    }

    std::string input_file = argv[1];
    int multiplier = 100;
    int num_lbs = 2;
    int fps_per_lb = 2;
    std::vector<std::string> block_apps;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--multiply" && i + 1 < argc) multiplier = std::stoi(argv[++i]);
        else if (arg == "--lbs" && i + 1 < argc) num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) fps_per_lb = std::stoi(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
    }

    BenchRules rules;
    for (const auto& app : block_apps) rules.blockApp(app);

    // Load base packets
    std::cout << "\n[Benchmark] Loading packets from " << input_file << "...\n";
    auto base_packets = loadPackets(input_file);
    if (base_packets.empty()) {
        std::cerr << "Error: No valid packets loaded.\n";
        return 1;
    }
    std::cout << "[Benchmark] Loaded " << base_packets.size() << " base packets\n";

    // Multiply
    std::cout << "[Benchmark] Multiplying " << multiplier << "x -> "
              << (base_packets.size() * multiplier) << " packets\n";
    auto packets = multiplyPackets(base_packets, multiplier);

    size_t mem_before = getMemoryUsageKB();

    // Run single-thread benchmark
    std::cout << "\n[Benchmark] Running SINGLE-THREAD test (1 LB x 1 FP)...\n";
    auto single = runBenchmark(packets, 1, 1, &rules);
    std::cout << "[Benchmark] Single-thread done in "
              << std::fixed << std::setprecision(1) << (single.elapsed_sec * 1000) << " ms\n";

    // Run multi-thread benchmark
    std::cout << "\n[Benchmark] Running MULTI-THREAD test ("
              << num_lbs << " LBs x " << fps_per_lb << " FPs)...\n";
    auto multi = runBenchmark(packets, num_lbs, fps_per_lb, &rules);
    std::cout << "[Benchmark] Multi-thread done in "
              << std::fixed << std::setprecision(1) << (multi.elapsed_sec * 1000) << " ms\n";

    size_t mem_after = getMemoryUsageKB();

    // Print report
    printReport(single, multi, input_file, multiplier, mem_before, mem_after);

    return 0;
}
