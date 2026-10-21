// IHB's experimental coverage-guided engine. No libFuzzer/AFL runtime.
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;
using Clock = std::chrono::steady_clock;
static uint32_t guard_count;
static uint32_t guard_capacity;
static volatile uint8_t *coverage;
static constexpr size_t kMaxInput = 4096;

extern "C" int IHBTestOneInput(const uint8_t *, size_t);
extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *end) {
    if (start == end || *start) return;
    for (auto p = start; p != end; ++p) *p = ++guard_count;
}
extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (coverage && *guard && *guard <= guard_capacity) coverage[*guard] = 1;
}

static Bytes read_bytes(const fs::path &path) {
    if (!fs::is_regular_file(path) || fs::is_symlink(path))
        throw std::runtime_error("input must be a regular file");
    if (fs::file_size(path) > kMaxInput) throw std::runtime_error("input exceeds 4096 bytes");
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read input");
    return Bytes(std::istreambuf_iterator<char>(input), {});
}
static void write_bytes(const fs::path &path, const Bytes &data) {
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char *>(data.data()), data.size());
    if (!output) throw std::runtime_error("cannot preserve input");
}
struct Random {
    uint64_t state;
    uint64_t next() { // Explicit PRNG so the schedule is independent of stdlib distributions.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }
    size_t pick(size_t n) { return next() % n; }
};
static Bytes mutate(Bytes input, Random &rng, unsigned operation) {
    if (input.empty()) input.push_back(0);
    const size_t at = rng.pick(input.size());
    switch (operation) {
        case 0: input[at] ^= uint8_t(1u << rng.pick(8)); break;
        case 1: input[at] = uint8_t(input[at] + (rng.pick(2) ? 1 : -1)); break;
        case 2: input[at] = uint8_t(rng.next()); break;
        case 3:
            if (input.size() < kMaxInput)
                input.insert(input.begin() + at, uint8_t(rng.next()));
            break;
        case 4: input.erase(input.begin() + at); break;
        case 5: {
            static constexpr uint8_t values[] = {0, 1, 3, 4, 7, 8, 16, 31, 32, 127, 128, 255};
            input[at] = values[rng.pick(sizeof(values))];
            break;
        }
    }
    return input;
}
struct Result { int signal = 0; int code = 0; bool timeout = false; };

static Result execute(const Bytes &input, const fs::path &log, unsigned timeout_ms) {
    std::memset(const_cast<uint8_t *>(coverage), 0, guard_count + 1);
    int fd = open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) throw std::runtime_error("cannot open case log");
    const pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) { close(fd); throw std::runtime_error("fork failed"); }
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(125);
        if (setpgid(0, 0) != 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
            _exit(125);
        close(fd);
        const rlimit core{0, 0};
        const rlimit file_limit{1024 * 1024, 1024 * 1024};
        if (setrlimit(RLIMIT_CORE, &core) != 0 || setrlimit(RLIMIT_FSIZE, &file_limit) != 0)
            _exit(125);
        const int code = IHBTestOneInput(input.data(), input.size());
        // _exit isolates per-input global state; LeakSanitizer exit hooks do not run.
        _exit(code == 0 ? 0 : 124);
    }
    close(fd);
    setpgid(child, child); // Also set from parent to close the timeout/group race.
    Result result;
    int status = 0;
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno != EINTR) throw std::runtime_error("waitpid failed");
        if (Clock::now() >= deadline) {
            result.timeout = true;
            kill(-child, SIGKILL);
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        usleep(1000);
    }
    // Clean up ordinary descendants in the case's process group.
    kill(-child, SIGKILL);
    if (WIFSIGNALED(status)) result.signal = WTERMSIG(status);
    if (WIFEXITED(status)) result.code = WEXITSTATUS(status);
    return result;
}

static uint64_t number(const char *text, uint64_t maximum) {
    std::string value(text);
    if (value.empty() || value.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("invalid positive integer");
    auto n = std::stoull(value);
    if (!n || n > maximum) throw std::runtime_error("integer out of range");
    return n;
}

int main(int argc, char **argv) {
    try {
        // Fixed positional interface is only invoked by run.py.
        if (argc != 8) throw std::runtime_error("usage: engine corpus out runs seed timeout_ms seconds replay-or-dash");
        const fs::path corpus_path = argv[1], out = argv[2];
        const auto runs = number(argv[3], 1000000);
        Random rng{number(argv[4], UINT64_MAX)};
        const auto timeout_ms = number(argv[5], 60000);
        const auto seconds = number(argv[6], 3600);
        const bool replay = std::string(argv[7]) != "-";
        if (!guard_count || guard_count > 10000000) throw std::runtime_error("missing or excessive coverage guards");
        void *map = mmap(nullptr, guard_count + 1, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED) throw std::runtime_error("coverage mapping failed");
        coverage = static_cast<volatile uint8_t *>(map);
        guard_capacity = guard_count;
        std::vector<uint8_t> seen(guard_count + 1);
        std::vector<fs::path> seeds;
        for (auto &entry : fs::directory_iterator(corpus_path)) seeds.push_back(entry.path());
        std::sort(seeds.begin(), seeds.end());
        if (seeds.empty()) throw std::runtime_error("empty corpus");
        std::vector<Bytes> corpus;
        for (auto &seed : seeds) corpus.push_back(read_bytes(seed));
        fs::create_directory(out / "retained");
        fs::create_directory(out / "findings");
        std::ofstream journal(out / "journal.jsonl");
        if (!journal) throw std::runtime_error("cannot create journal");
        const auto start = Clock::now();
        size_t executions = 0, findings = 0, retained = 0, edges = 0;
        bool budget_exhausted = false;
        const auto initial_count = corpus.size();
        const Bytes replay_input = replay ? read_bytes(argv[7]) : Bytes{};
        for (size_t i = 0; i < (replay ? 1 : runs); ++i) {
            if (Clock::now() - start >= std::chrono::seconds(seconds)) {
                budget_exhausted = true;
                break;
            }
            size_t parent = i < initial_count ? i : rng.pick(corpus.size());
            unsigned operation = i % 6;
            Bytes input = replay ? replay_input : (i < initial_count ? corpus[parent] : mutate(corpus[parent], rng, operation));
            auto result = execute(input, out / "current.log", timeout_ms);
            size_t new_edges = 0;
            const bool failed = result.timeout || result.signal || result.code;
            // Crashing/timeout coverage cannot change the corpus-selection state.
            if (!failed) {
                for (size_t edge = 1; edge <= guard_count; ++edge)
                    if (coverage[edge] && !seen[edge]) { seen[edge] = 1; ++new_edges; }
                edges += new_edges;
            }
            if (new_edges && i >= initial_count && !replay) {
                if (corpus.size() < 4096) {
                    corpus.push_back(input);
                    write_bytes(out / "retained" / ("case-" + std::to_string(i) + ".bin"), input);
                    ++retained;
                }
            }
            if (failed) {
                auto prefix = out / "findings" / ("case-" + std::to_string(i));
                write_bytes(prefix.string() + ".bin", input);
                fs::rename(out / "current.log", prefix.string() + ".log");
                ++findings;
            } else fs::remove(out / "current.log");
            journal << "{\"case\":" << i << ",\"parent\":" << parent
                    << ",\"mutation\":" << (i < initial_count || replay ? -1 : int(operation))
                    << ",\"bytes\":" << input.size() << ",\"new_edges\":" << new_edges
                    << ",\"signal\":" << result.signal << ",\"exit\":" << result.code
                    << ",\"timeout\":" << (result.timeout ? "true" : "false") << "}\n";
            journal.flush();
            if (!journal) throw std::runtime_error("cannot preserve journal");
            ++executions;
            // First failure is preserved and stops the bounded campaign.
            if (failed) break;
        }
        std::ofstream summary(out / "summary.json");
        summary << "{\"engine\":\"ihb-native-v0\",\"executions\":" << executions
                << ",\"findings\":" << findings << ",\"guards\":" << guard_count
                << ",\"edges\":" << edges << ",\"retained\":" << retained
                << ",\"corpus_size\":" << corpus.size()
                << ",\"budget_exhausted\":" << (budget_exhausted ? "true" : "false") << "}\n";
        if (!summary) throw std::runtime_error("cannot preserve summary");
        munmap(const_cast<uint8_t *>(coverage), guard_count + 1);
        coverage = nullptr;
        return findings ? 1 : 0;
    } catch (const std::exception &error) {
        std::cerr << "ihb engine error: " << error.what() << '\n';
        return 2;
    }
}
