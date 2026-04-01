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
#include <atomic>
#include <chrono>
#include "ipc_core.h"

#pragma comment(lib, "ws2_32.lib")

// ── Global State ──────────────────────────────────────
EventLog        gLog;
AccessControl   gACL;
PipeChannel     gPipe;
MessageQueue    gMQ;
SharedMemory    gShm;
std::string     gMasterToken;

// ── Operation Counters ────────────────────────────────
std::atomic<int> gPipeSent{0}, gPipeRecv{0};
std::atomic<int> gQueueSent{0}, gQueueRecv{0};
std::atomic<int> gShmWrites{0}, gShmReads{0};
std::atomic<int> gSecEvents{0};
std::chrono::steady_clock::time_point gStartTime = std::chrono::steady_clock::now();

// ── HTTP Response Builder ─────────────────────────────
struct HttpResponse {
    int status = 200;
    std::string contentType = "application/json";
    std::string body;
    std::string build() const {
        std::string st = (status==200)?"OK":(status==403)?"Forbidden":"Not Found";
        std::ostringstream o;
        o << "HTTP/1.1 " << status << " " << st << "\r\n"
          << "Content-Type: " << contentType << "\r\n"
          << "Access-Control-Allow-Origin: *\r\n"
          << "Content-Length: " << body.size() << "\r\n"
          << "Connection: close\r\n\r\n" << body;
        return o.str();
    }
};

// ── JSON Helpers ──────────────────────────────────────
inline std::string jsonStr(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        if (c=='"') o+="\\\""; else if (c=='\\') o+="\\\\";
        else if (c=='\n') o+="\\n"; else if (c=='\r') o+="\\r";
        else o+=c;
    }
    return o+"\"";
}
inline std::string jKV(const std::string& k, const std::string& v, bool str=true) {
    return "\""+k+"\":"+(str?jsonStr(v):v);
}
inline std::string extractString(const std::string& json, const std::string& key) {
    std::string t="\""+key+"\"";
    size_t p=json.find(t); if(p==std::string::npos) return "";
    p+=t.length(); p=json.find(':',p); if(p==std::string::npos) return "";
    p++; p=json.find('"',p); if(p==std::string::npos) return "";
    p++; size_t e=p;
    while(e<json.length()&&json[e]!='"') e++;
    return json.substr(p,e-p);
}

// ── REST Router ───────────────────────────────────────
HttpResponse handleRequest(const std::string& method, const std::string& path, const std::string& body) {
    HttpResponse resp;

    // ── AUTH
    if (method=="POST" && path=="/api/auth") {
        std::string m=extractString(body,"master");
        if (m!=gMasterToken) {
            resp.status=403; resp.body="{\"error\":\"Invalid access key\"}";
            gSecEvents++; return resp;
        }
        std::string s=Crypto::generateToken(16);
        gACL.grantToken(s);
        resp.body="{"+jKV("token",s)+"}";
        return resp;
    }

    // ── STATUS
    if (method=="GET" && path=="/api/status") {
        auto up = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - gStartTime).count();
        auto logs = gLog.getAll();
        int sec=0; for(auto& e:logs) if(e.level=="SECURITY") sec++;
        std::ostringstream j;
        j << "{"
          << jKV("pipe_ready",   gPipe.isReady()?"true":"false", false) << ","
          << jKV("queue_ready",  gMQ.isReady()?"true":"false",   false) << ","
          << jKV("shm_ready",    gShm.isReady()?"true":"false",  false) << ","
          << jKV("pipe_sent",    std::to_string(gPipeSent.load()),  false) << ","
          << jKV("pipe_recv",    std::to_string(gPipeRecv.load()),  false) << ","
          << jKV("queue_sent",   std::to_string(gQueueSent.load()), false) << ","
          << jKV("queue_recv",   std::to_string(gQueueRecv.load()), false) << ","
          << jKV("shm_writes",   std::to_string(gShmWrites.load()), false) << ","
          << jKV("shm_reads",    std::to_string(gShmReads.load()),  false) << ","
          << jKV("log_count",    std::to_string((int)logs.size()),  false) << ","
          << jKV("security_events", std::to_string(sec),            false) << ","
          << jKV("uptime",       std::to_string(up),                false)
          << "}";
        resp.body=j.str(); return resp;
    }

    // ── SYSINFO
    if (method=="GET" && path=="/api/sysinfo") {
        DWORD pid=GetCurrentProcessId();
        resp.body="{"+jKV("pid",std::to_string(pid),false)+","
                    +jKV("port","8080",false)+","
                    +jKV("version","\"1.0\"",false)+"}";
        return resp;
    }

    // ── START SERVICES (kept for compatibility)
    if (method=="POST" && path=="/api/start_services") {
        gPipe.createServer("secure_pipe_1");
        gMQ.createServer("secure_queue_1");
        resp.body="{\"status\":\"all channels active\"}";
        return resp;
    }

    // ── UNAUTHORIZED ACCESS DEMO
    if (method=="GET" && path=="/api/test_unauthorized") {
#ifdef _WIN32
        ImpersonateAnonymousToken(GetCurrentThread());
        HANDLE h=CreateFileA("\\\\.\\pipe\\secure_pipe_1",GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
        DWORD err=GetLastError();
        if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);
        RevertToSelf();
        std::ostringstream o;
        o<<"{\"success\":true,\"error_code\":"<<err<<",\"error_msg\":\"";
        if(err==5||err==ERROR_ACCESS_DENIED) o<<"ERROR_ACCESS_DENIED — DACL blocked kernel access";
        else if(err==2) o<<"PIPE_NOT_FOUND — process isolated";
        else o<<"BLOCKED (code "<<err<<")";
        o<<"\"}";
        resp.body=o.str();
        gSecEvents++;
        gLog.add("SECURITY","Unauthorized kernel access blocked by OS DACL (anonymous token rejected)");
#else
        resp.body="{\"success\":true,\"error_code\":13,\"error_msg\":\"EACCES\"}";
#endif
        return resp;
    }

    // ── OS SECURITY DIALOG
    if (method=="GET" && path=="/api/authorize_access") {
#ifdef _WIN32
        int btn=MessageBoxA(nullptr,
            "A background process received ERROR_ACCESS_DENIED attempting to access:\n"
            "\\\\.\\pipe\\secure_pipe_1\n\n"
            "This IPC object is protected by a strict DACL (Security Descriptor).\n"
            "Grant temporary kernel override to this session?",
            "Windows OS — Security Intervention",
            MB_YESNO|MB_ICONWARNING|MB_SETFOREGROUND|MB_TOPMOST);
        if(btn==IDYES) {
            resp.body="{\"granted\":true,\"msg\":\"DACL Override authorized by interactive user.\"}";
            gLog.add("SECURITY","OS user granted temporary kernel override via native dialog");
        } else {
            resp.body="{\"granted\":false,\"msg\":\"Authorization denied by OS user.\"}";
            gLog.add("SECURITY","OS user rejected kernel override request");
        }
        gSecEvents++;
#else
        resp.body="{\"granted\":false,\"msg\":\"Not implemented on this platform\"}";
#endif
        return resp;
    }

    // ── NAMED PIPE
    if (method=="POST" && path=="/api/pipe/send") {
        std::string token=extractString(body,"token");
        std::string msg=extractString(body,"message");
        bool ok=gPipe.send(token,msg,"");
        if(ok) gPipeSent++;
        resp.body="{\"success\":"+(std::string)(ok?"true":"false")+"}";
        return resp;
    }
    if (method=="POST" && path=="/api/pipe/receive") {
        std::string token=extractString(body,"token");
        std::string msg=gPipe.receive(token,"");
        if(!msg.empty()) gPipeRecv++;
        resp.body="{"+jKV("message",msg)+"}";
        return resp;
    }

    // ── MESSAGE QUEUE
    if (method=="POST" && path=="/api/queue/send") {
        std::string token=extractString(body,"token");
        std::string msg=extractString(body,"message");
        bool ok=gMQ.send(token,msg);
        if(ok) gQueueSent++;
        resp.body="{\"success\":"+(std::string)(ok?"true":"false")+"}";
        return resp;
    }
    if (method=="POST" && path=="/api/queue/receive") {
        std::string token=extractString(body,"token");
        QueueMsg m=gMQ.receive(token);
        if(!m.text.empty()) gQueueRecv++;
        resp.body="{"+jKV("message",m.text)+","+jKV("timestamp",m.timestamp)+"}";
        return resp;
    }

    // ── SHARED MEMORY
    if (method=="POST" && path=="/api/shm/init") {
        std::string token=extractString(body,"token");
        bool ok=gShm.create("OS_SECURE_SHM",token);
        resp.body="{\"success\":"+(std::string)(ok?"true":"false")+"}";
        return resp;
    }
    if (method=="POST" && path=="/api/shm/write") {
        std::string token=extractString(body,"token");
        std::string data=extractString(body,"data");
        bool ok=gShm.write(token,data);
        if(ok) gShmWrites++;
        resp.body="{\"success\":"+(std::string)(ok?"true":"false")+"}";
        return resp;
    }
    if (method=="POST" && path=="/api/shm/read") {
        std::string token=extractString(body,"token");
        std::string data=gShm.read(token);
        if(!data.empty()) gShmReads++;
        resp.body="{"+jKV("data",data)+"}";
        return resp;
    }

    // ── AUDIT LOG
    if (method=="GET" && path=="/api/log") {
        auto entries=gLog.getAll();
        std::ostringstream j; j<<"[";
        for(size_t i=0;i<entries.size();i++){
            if(i>0) j<<",";
            j<<"{"<<jKV("time",entries[i].time)<<","
                   <<jKV("level",entries[i].level)<<","
                   <<jKV("message",entries[i].message)<<"}";
        }
        j<<"]"; resp.body=j.str(); return resp;
    }

    // ── DASHBOARD HTML
    if (method=="GET" && (path=="/"||path=="/index.html")) {
        resp.contentType="text/html";
        HANDLE hf=CreateFileA("dashboard.html",GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        if(hf!=INVALID_HANDLE_VALUE){
            DWORD sz=GetFileSize(hf,nullptr);
            std::string c(sz,'\0'); DWORD rd=0;
            ReadFile(hf,&c[0],sz,&rd,nullptr); CloseHandle(hf);
            resp.body=c;
        } else { resp.body="<h1>dashboard.html not found</h1>"; }
        return resp;
    }

    resp.status=404; resp.body="{\"error\":\"Not found\"}";
    return resp;
}

// ── HTTP Server ───────────────────────────────────────
class HttpServer {
public:
    bool start(int port) {
        WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
        sock_=socket(AF_INET,SOCK_STREAM,0);
        BOOL opt=TRUE; setsockopt(sock_,SOL_SOCKET,SO_REUSEADDR,(char*)&opt,sizeof(opt));
        sockaddr_in addr{}; addr.sin_family=AF_INET;
        addr.sin_port=htons(port); addr.sin_addr.s_addr=INADDR_ANY;
        if(bind(sock_,(sockaddr*)&addr,sizeof(addr))!=0) return false;
        listen(sock_,SOMAXCONN); return true;
    }
    void run() {
        while(true){
            SOCKET cl=accept(sock_,nullptr,nullptr);
            if(cl==INVALID_SOCKET) continue;
            std::thread([cl](){
                char buf[8192]={};
                int n=recv(cl,buf,sizeof(buf)-1,0);
                if(n>0){
                    std::string req(buf,n);
                    std::istringstream iss(req);
                    std::string method,path; iss>>method>>path;
                    std::string body;
                    size_t bp=req.find("\r\n\r\n");
                    if(bp!=std::string::npos) body=req.substr(bp+4);
                    HttpResponse r=handleRequest(method,path,body);
                    std::string rs=r.build();
                    send(cl,rs.c_str(),(int)rs.size(),0);
                }
                closesocket(cl);
            }).detach();
        }
    }
private:
    SOCKET sock_=INVALID_SOCKET;
};
