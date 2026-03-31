#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include "ipc_core.h"

#pragma comment(lib, "ws2_32.lib")

struct HttpResponse {
    int status = 200;
    std::string contentType = "application/json";
    std::string body;

    std::string build() const {
        std::string statusText = (status == 200) ? "OK" : (status == 403) ? "Forbidden" : "Bad Request";
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status << " " << statusText << "\r\n"
            << "Content-Type: " << contentType << "\r\n"
            << "Access-Control-Allow-Origin: *\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n\r\n"
            << body;
        return oss.str();
    }
};

inline std::string jsonStr(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out + "\"";
}
inline std::string jsonKV(const std::string& k, const std::string& v, bool isStr = true) {
    return "\"" + k + "\":" + (isStr ? jsonStr(v) : v);
}

inline std::string extractString(const std::string& json, const std::string& key) {
    std::string target = "\"" + key + "\"";
    size_t pos = json.find(target);
    if (pos == std::string::npos) return "";
    pos += target.length();
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    pos++;
    size_t endpos = pos;
    while (endpos < json.length() && json[endpos] != '"') endpos++;
    return json.substr(pos, endpos - pos);
}

// Global OS-Specific IPC Instances
EventLog gLog;
AccessControl gACL;
PipeChannel gPipe;
MessageQueue gMQ;
SharedMemory gShm;
std::string gMasterToken;

// Clean router focusing only on 3 components + auth
HttpResponse handleRequest(const std::string& method, const std::string& path, const std::string& body) {
    HttpResponse resp;

    // ── AUTHENTICATION 
    if (method == "POST" && path == "/api/auth") {
        std::string tokenInput = extractString(body, "master");
        if (tokenInput != gMasterToken) {
            resp.status = 403;
            resp.body = "{\"error\":\"Invalid Master Key\"}";
            return resp;
        }
        std::string session = Crypto::generateToken(16);
        gACL.grantToken(session);
        resp.body = "{" + jsonKV("token", session) + "}";
        return resp;
    }

    // ── START ALL SERVICES
    if (method == "POST" && path == "/api/start_services") {
        gPipe.createServer("secure_pipe_1");
        gMQ.createServer("secure_queue_1");
        resp.body = "{\"status\":\"started\"}";
        return resp;
    }

    // ── TEST UNAUTHORIZED OS ACCESS
    if (method == "GET" && path == "/api/test_unauthorized") {
#ifdef _WIN32
        ImpersonateAnonymousToken(GetCurrentThread());
        HANDLE h = CreateFileA("\\\\.\\pipe\\secure_pipe_1", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        DWORD err = GetLastError();
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        RevertToSelf();
        
        std::ostringstream oss;
        oss << "{\"success\": true, \"error_code\": " << err << ", \"error_msg\": \"";
        if (err == ERROR_ACCESS_DENIED || err == 5) oss << "ERROR_ACCESS_DENIED";
        else if (err == 2) oss << "ACCESS_DENIED_NATIVE (Process Isolated)";
        else oss << "UNKNOWN_ERROR (Code " << err << ")";
        oss << "\"}";
        resp.body = oss.str();
        gLog.add("SECURITY", "Unauthorized kernel access blocked by OS DACL.");
#else
        resp.body = "{\"success\": true, \"error_code\": 13, \"error_msg\": \"EACCES\"}";
#endif
        return resp;
    }

    // ── NATIVE PERMISSION DIALOG
    if (method == "GET" && path == "/api/authorize_access") {
#ifdef _WIN32
        // Trigger a native Windows Operating System UI pop-up dialog
        int btn = MessageBoxA(nullptr,
            "A background process has encountered an ERROR_ACCESS_DENIED exception "
            "attempting to interact with the Native Pipe: '\\\\.\\pipe\\secure_pipe_1'.\n\n"
            "This component is isolated by a strict Security Descriptor (DACL).\n"
            "Do you want to grant temporary Kernel Override privileges to this session?",
            "Windows OS Security Intervention",
            MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
            
        if (btn == IDYES) {
            resp.body = "{\"granted\": true, \"msg\": \"DACL Override Authorized by Interactive User.\"}";
            gLog.add("SECURITY", "OS User explicitly granted temporary Kernel Override.");
        } else {
            resp.body = "{\"granted\": false, \"msg\": \"Authorization Denied.\"}";
            gLog.add("SECURITY", "OS User explicitly rejected Kernel Override request.");
        }
#else
        resp.body = "{\"granted\": false, \"msg\": \"Not implemented\"}";
#endif
        return resp;
    }

    // ── NAMED PIPE 
    if (method == "POST" && path == "/api/pipe/send") {
        std::string token = extractString(body, "token");
        std::string message = extractString(body, "message");
        bool ok = gPipe.send(token, message, ""); // No XOR extra steps to keep UI simple
        resp.body = "{\"success\":" + std::string(ok ? "true" : "false") + "}";
        return resp;
    }
    if (method == "POST" && path == "/api/pipe/receive") {
        std::string token = extractString(body, "token");
        std::string msg = gPipe.receive(token, "");
        resp.body = "{" + jsonKV("message", msg) + "}";
        return resp;
    }

    // ── MESSAGE QUEUE 
    if (method == "POST" && path == "/api/queue/send") {
        std::string token = extractString(body, "token");
        std::string message = extractString(body, "message");
        bool ok = gMQ.send(token, message);
        resp.body = "{\"success\":" + std::string(ok ? "true" : "false") + "}";
        return resp;
    }
    if (method == "POST" && path == "/api/queue/receive") {
        std::string token = extractString(body, "token");
        QueueMsg msg = gMQ.receive(token);
        resp.body = "{" + jsonKV("message", msg.text) + "}";
        return resp;
    }

    // ── SHARED MEMORY 
    if (method == "POST" && path == "/api/shm/init") {
        std::string token = extractString(body, "token");
        bool ok = gShm.create("OS_SECURE_SHM", token);
        resp.body = "{\"success\":" + std::string(ok ? "true" : "false") + "}";
        return resp;
    }
    if (method == "POST" && path == "/api/shm/write") {
        std::string token = extractString(body, "token");
        std::string data = extractString(body, "data");
        bool ok = gShm.write(token, data);
        resp.body = "{\"success\":" + std::string(ok ? "true" : "false") + "}";
        return resp;
    }
    if (method == "POST" && path == "/api/shm/read") {
        std::string token = extractString(body, "token");
        std::string data = gShm.read(token);
        resp.body = "{" + jsonKV("data", data) + "}";
        return resp;
    }

    // ── LOGS 
    if (method == "GET" && path == "/api/log") {
        auto entries = gLog.getAll();
        std::ostringstream j; j << "[";
        for (size_t i = 0; i < entries.size(); i++) {
            if (i > 0) j << ",";
            j << "{" << jsonKV("time", entries[i].time) << ","
              << jsonKV("level", entries[i].level) << ","
              << jsonKV("message", entries[i].message) << "}";
        }
        j << "]";
        resp.body = j.str();
        return resp;
    }

    // ── DASHBOARD HTML 
    if (method == "GET" && (path == "/" || path == "/index.html")) {
        resp.contentType = "text/html";
        HANDLE hFile = CreateFileA("dashboard.html", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD sz = GetFileSize(hFile, nullptr);
            std::string content(sz, '\0');
            DWORD read = 0; ReadFile(hFile, &content[0], sz, &read, nullptr);
            CloseHandle(hFile);
            resp.body = content;
        } else {
            resp.body = "<h1>UI Missing</h1><p>dashboard.html not found.</p>";
        }
        return resp;
    }

    resp.status = 404;
    resp.body = "{\"error\":\"Not found\"}";
    return resp;
}

class HttpServer {
public:
    bool start(int port) {
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        BOOL opt = TRUE; setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sock_, (sockaddr*)&addr, sizeof(addr)) != 0) return false;
        listen(sock_, SOMAXCONN);
        return true;
    }
    void run() {
        while (true) {
            SOCKET client = accept(sock_, nullptr, nullptr);
            if (client == INVALID_SOCKET) continue;
            std::thread([client]() {
                char buf[8192] = {};
                int received = recv(client, buf, sizeof(buf) - 1, 0);
                if (received > 0) {
                    std::string req(buf, received);
                    std::istringstream iss(req);
                    std::string method, path; iss >> method >> path;
                    std::string body;
                    size_t bodyPos = req.find("\r\n\r\n");
                    if (bodyPos != std::string::npos) body = req.substr(bodyPos + 4);
                    HttpResponse resp = handleRequest(method, path, body);
                    std::string response = resp.build();
                    send(client, response.c_str(), (int)response.size(), 0);
                }
                closesocket(client);
            }).detach();
        }
    }
private:
    SOCKET sock_ = INVALID_SOCKET;
};
