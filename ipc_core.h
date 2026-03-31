#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#ifdef _WIN32
  #include <windows.h>
  #include <sddl.h>
#else
  // Future POSIX OS support placeholder
  #include <unistd.h>
#endif

#include <string>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

// ═══════════════════════════════════════════════════
//  OS Abstracted Security (Real OS-Level Integration)
// ═══════════════════════════════════════════════════
namespace OSSecurity {
#ifdef _WIN32
    // Creates a SECURITY_ATTRIBUTES structure strictly limiting access 
    // to Administrators (BA), the System (SY), and the Current User (CU).
    // This blocks unauthorized processes from attaching to our IPC channels.
    inline bool CreateStrictSecurityAttributes(SECURITY_ATTRIBUTES* sa, PSECURITY_DESCRIPTOR* pSD) {
        // SDDL String: D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;CU)
        // Discretionary ACL:
        // A;;GA;;;BA -> Allow GA (Generic All) to BA (Built-in Admins)
        // A;;GA;;;SY -> Allow GA to SY (Local System)
        // A;;GA;;;CU -> Allow GA to CU (Interactive User)
        // Implicitly denies all others.
        const char* sddl = "D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;CU)";
        
        bool ok = ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, pSD, nullptr);
            
        if (!ok) return false;
        
        sa->nLength = sizeof(SECURITY_ATTRIBUTES);
        sa->lpSecurityDescriptor = *pSD;
        sa->bInheritHandle = FALSE;
        return true;
    }
    
    inline void FreeSecurityAttributes(PSECURITY_DESCRIPTOR pSD) {
        if (pSD) LocalFree(pSD);
    }
#else
    // POSIX Implementation placeholder (chmod, chown, etc.)
#endif
}

// ═══════════════════════════════════════════════════
//  Crypto — XOR cipher + secure token generator
// ═══════════════════════════════════════════════════
namespace Crypto {
    inline std::string xorEncrypt(const std::string& data, const std::string& key) {
        if (key.empty()) return data;
        std::string out = data;
        for (size_t i = 0; i < data.size(); i++)
            out[i] = data[i] ^ key[i % key.size()];
        return out;
    }
    inline std::string generateToken(size_t len = 32) {
        static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<> dist(0, (int)(sizeof(chars) - 2));
        std::string tok(len, ' ');
        for (auto& c : tok) c = chars[dist(rng)];
        return tok;
    }
}

// ═══════════════════════════════════════════════════
//  Event Log — thread-safe
// ═══════════════════════════════════════════════════
struct LogEntry { std::string time, level, message; };

class EventLog {
public:
    void add(const std::string& level, const std::string& msg) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char buf[32]; struct tm tmi; localtime_s(&tmi, &t);
        strftime(buf, sizeof(buf), "%H:%M:%S", &tmi);
        entries_.push_back({ buf, level, msg });
        if (entries_.size() > 500) entries_.erase(entries_.begin());
    }
    std::vector<LogEntry> getAll() {
        std::lock_guard<std::mutex> lk(mtx_); return entries_;
    }
private:
    std::vector<LogEntry> entries_;
    std::mutex mtx_;
};
extern EventLog gLog;

// ═══════════════════════════════════════════════════
//  Access Control List (Web Dashboard Layer)
// ═══════════════════════════════════════════════════
class AccessControl {
public:
    void grantToken(const std::string& t) {
        std::lock_guard<std::mutex> lk(mtx_); tokens_.insert(t);
        gLog.add("SECURITY", "Web UI token granted");
    }
    bool isAuthorized(const std::string& t) {
        std::lock_guard<std::mutex> lk(mtx_);
        bool ok = tokens_.count(t) > 0;
        if (!ok && !t.empty())
            gLog.add("SECURITY", "Unauthorized dashboard attempt blocked.");
        return ok;
    }
private:
    std::set<std::string> tokens_;
    std::mutex mtx_;
};
extern AccessControl gACL;

// ═══════════════════════════════════════════════════
//  Named Pipe Channel (1-to-1)
// ═══════════════════════════════════════════════════
class PipeChannel {
public:
    ~PipeChannel() { stop(); }

    bool createServer(const std::string& name) {
        if (running_.load()) return true;
        
#ifdef _WIN32
        pipeName_ = "\\\\.\\pipe\\" + name;
        
        SECURITY_ATTRIBUTES sa{};
        PSECURITY_DESCRIPTOR pSD = nullptr;
        OSSecurity::CreateStrictSecurityAttributes(&sa, &pSD);

        hPipe_ = CreateNamedPipeA(
            pipeName_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa); // Apply OS Security
            
        OSSecurity::FreeSecurityAttributes(pSD);

        if (hPipe_ == INVALID_HANDLE_VALUE) {
            gLog.add("ERROR", "Native OS Pipe creation failed.");
            return false;
        }
        running_ = true;
        listenerThread_ = std::thread(&PipeChannel::listenLoop, this);
        gLog.add("INFO", "Secured OS Named Pipe created.");
        return true;
#else
        return false;
#endif
    }

    bool send(const std::string& token, const std::string& data, const std::string& encKey = "") {
        if (!gACL.isAuthorized(token)) return false;
        
        std::string payload = encKey.empty() ? data : Crypto::xorEncrypt(data, encKey);
        
#ifdef _WIN32
        WaitNamedPipeA(pipeName_.c_str(), 2000);
        HANDLE h = CreateFileA(pipeName_.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        
        DWORD written = 0;
        WriteFile(h, payload.c_str(), (DWORD)payload.size(), &written, nullptr);
        CloseHandle(h);
        
        gLog.add("INFO", "Data injected into Named Pipe.");
        return written > 0;
#else
        return false;
#endif
    }

    std::string receive(const std::string& token, const std::string& encKey = "") {
        if (!gACL.isAuthorized(token)) return "";
        std::lock_guard<std::mutex> lk(bufMtx_);
        if (rxQueue_.empty()) return "";
        std::string msg = rxQueue_.front();
        rxQueue_.pop_front();
        std::string result = encKey.empty() ? msg : Crypto::xorEncrypt(msg, encKey);
        gLog.add("INFO", "Data consumed from Named Pipe.");
        return result;
    }

    bool isReady() const { return running_.load(); }

    void stop() {
        running_ = false;
#ifdef _WIN32
        HANDLE dummy = CreateFileA(pipeName_.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (dummy != INVALID_HANDLE_VALUE) CloseHandle(dummy);
        if (hPipe_ != INVALID_HANDLE_VALUE) { CloseHandle(hPipe_); hPipe_ = INVALID_HANDLE_VALUE; }
#endif
        if (listenerThread_.joinable()) listenerThread_.detach();
    }

private:
#ifdef _WIN32
    void listenLoop() {
        while (running_.load()) {
            BOOL ok = ConnectNamedPipe(hPipe_, nullptr);
            if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
                if (!running_.load()) break;
                Sleep(10); continue;
            }
            if (!running_.load()) break;

            char buf[4096] = {};
            DWORD read = 0;
            ReadFile(hPipe_, buf, sizeof(buf) - 1, &read, nullptr);
            if (read > 0) {
                std::lock_guard<std::mutex> lk(bufMtx_);
                rxQueue_.push_back(std::string(buf, read));
            }
            DisconnectNamedPipe(hPipe_);
        }
    }
    HANDLE hPipe_ = INVALID_HANDLE_VALUE;
#endif
    std::string pipeName_;
    std::thread listenerThread_;
    std::atomic<bool> running_{ false };
    std::deque<std::string> rxQueue_;
    std::mutex bufMtx_;
};

// ═══════════════════════════════════════════════════
//  Message Queue (1-to-Many Mailslot)
// ═══════════════════════════════════════════════════
struct QueueMsg { std::string text; std::string timestamp; };

class MessageQueue {
public:
    ~MessageQueue() { close(); }

    bool createServer(const std::string& name) {
#ifdef _WIN32
        if (hSlot_ != INVALID_HANDLE_VALUE) return true;
        slotName_ = "\\\\.\\mailslot\\" + name;
        
        SECURITY_ATTRIBUTES sa{};
        PSECURITY_DESCRIPTOR pSD = nullptr;
        OSSecurity::CreateStrictSecurityAttributes(&sa, &pSD);

        hSlot_ = CreateMailslotA(slotName_.c_str(), 0, MAILSLOT_WAIT_FOREVER, &sa); // Apply OS Security
        OSSecurity::FreeSecurityAttributes(pSD);

        if (hSlot_ == INVALID_HANDLE_VALUE) return false;
        gLog.add("INFO", "Secured OS Mailslot Queue created.");
        return true;
#else
        return false;
#endif
    }

    bool send(const std::string& token, const std::string& msg) {
        if (!gACL.isAuthorized(token)) return false;
#ifdef _WIN32
        HANDLE h = CreateFileA(slotName_.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        
        DWORD written = 0;
        WriteFile(h, msg.c_str(), (DWORD)msg.size(), &written, nullptr);
        CloseHandle(h);
        gLog.add("INFO", "Message enqueued to Mailslot.");
        return true;
#else
        return false;
#endif
    }

    QueueMsg receive(const std::string& token) {
        if (!gACL.isAuthorized(token)) return {"",""};
#ifdef _WIN32
        DWORD msgSize = 0, msgCount = 0;
        GetMailslotInfo(hSlot_, nullptr, &msgSize, &msgCount, nullptr);
        if (msgCount == 0 || msgSize == MAILSLOT_NO_MESSAGE) return {"",""};
        
        std::vector<char> buf(msgSize);
        DWORD read = 0;
        ReadFile(hSlot_, buf.data(), msgSize, &read, nullptr);
        std::string text(buf.begin(), buf.end());
        
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char tbuf[32]; struct tm tmi; localtime_s(&tmi, &t);
        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tmi);
        gLog.add("INFO", "Message dequeued from Mailslot.");
        
        return {text, tbuf};
#else
        return {"",""};
#endif
    }

    bool isReady() const {
#ifdef _WIN32
        return hSlot_ != INVALID_HANDLE_VALUE;
#else
        return false;
#endif
    }
    
    void close() {
#ifdef _WIN32
        if (hSlot_ != INVALID_HANDLE_VALUE) { CloseHandle(hSlot_); hSlot_ = INVALID_HANDLE_VALUE; }
#endif
    }

private:
#ifdef _WIN32
    HANDLE hSlot_ = INVALID_HANDLE_VALUE;
#endif
    std::string slotName_;
};

// ═══════════════════════════════════════════════════
//  Shared Memory (Synchronous Memory Layout)
// ═══════════════════════════════════════════════════
struct ShmHeader { LONG lock; DWORD dataSize; char data[4080]; };

class SharedMemory {
public:
    ~SharedMemory() { close(); }

    bool create(const std::string& name, const std::string& token) {
        if (!gACL.isAuthorized(token)) return false;
#ifdef _WIN32
        if (shm_) return true;
        
        SECURITY_ATTRIBUTES sa{};
        PSECURITY_DESCRIPTOR pSD = nullptr;
        OSSecurity::CreateStrictSecurityAttributes(&sa, &pSD);

        hMap_ = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(ShmHeader), name.c_str());
        OSSecurity::FreeSecurityAttributes(pSD);
        
        if (!hMap_) return false;
        
        shm_ = (ShmHeader*)MapViewOfFile(hMap_, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!shm_) { CloseHandle(hMap_); hMap_ = nullptr; return false; }
        ZeroMemory(shm_, sizeof(ShmHeader));
        gLog.add("INFO", "Secured Shared Memory block mapped.");
        return true;
#else
        return false;
#endif
    }

    bool write(const std::string& token, const std::string& data) {
        if (!gACL.isAuthorized(token)) return false;
#ifdef _WIN32
        if (!shm_) return false;
        while (InterlockedCompareExchange(&shm_->lock, 1, 0) != 0) Sleep(0);
        size_t len = std::min(data.size(), sizeof(shm_->data) - 1);
        memcpy(shm_->data, data.c_str(), len);
        shm_->data[len] = 0;
        shm_->dataSize = (DWORD)len;
        InterlockedExchange(&shm_->lock, 0);
        gLog.add("INFO", "Shared Memory written successfully.");
        return true;
#else
        return false;
#endif
    }

    std::string read(const std::string& token) {
        if (!gACL.isAuthorized(token)) return "";
#ifdef _WIN32
        if (!shm_) return "";
        while (InterlockedCompareExchange(&shm_->lock, 1, 0) != 0) Sleep(0);
        std::string result(shm_->data, shm_->dataSize);
        InterlockedExchange(&shm_->lock, 0);
        gLog.add("INFO", "Shared Memory read by user.");
        return result;
#else
        return "";
#endif
    }

    bool isReady() const { return shm_ != nullptr; }

    void close() {
#ifdef _WIN32
        if (shm_) { UnmapViewOfFile(shm_); shm_ = nullptr; }
        if (hMap_) { CloseHandle(hMap_); hMap_ = nullptr; }
#endif
    }

private:
#ifdef _WIN32
    HANDLE hMap_ = nullptr;
    ShmHeader* shm_ = nullptr;
#else
    void* shm_ = nullptr;
#endif
};
