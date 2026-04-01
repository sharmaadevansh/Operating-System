#include "http_server.h"
#include <iostream>
#include <cstdio>
#include <shellapi.h>

int main() {
    printf("\n");
    printf("  +==================================================+\n");
    printf("  |  IPC FRAMEWORK  v1.0  --  C++17 / WinAPI        |\n");
    printf("  |  Named Pipes  |  Mailslots  |  Shared Memory     |\n");
    printf("  |  OS DACL Security  |  Winsock2 HTTP Server       |\n");
    printf("  +==================================================+\n\n");

    // Fixed access key — pre-authorized as active session
    gMasterToken = "IPC2026SECURE";
    gACL.grantToken("IPC2026SECURE");

    // Boot all IPC channels immediately
    gPipe.createServer("secure_pipe_1");
    gMQ.createServer("secure_queue_1");
    gShm.create("OS_SECURE_SHM", "IPC2026SECURE");

    gLog.add("INFO",     "IPC Framework v1.0 — Boot sequence complete");
    gLog.add("INFO",     "Named Pipe initialized: \\\\.\\pipe\\secure_pipe_1");
    gLog.add("INFO",     "Mailslot Queue initialized: \\\\.\\mailslot\\secure_queue_1");
    gLog.add("INFO",     "Shared Memory mapped: OS_SECURE_SHM (4 KB)");
    gLog.add("SECURITY", "DACL applied — D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;CU)");
    gLog.add("SECURITY", "Access key pre-authorized. Session active.");

    printf("  [+] Named Pipe   : \\\\.\\pipe\\secure_pipe_1  [READY]\n");
    printf("  [+] Mailslot     : \\\\.\\mailslot\\secure_queue_1  [READY]\n");
    printf("  [+] Shared Mem   : OS_SECURE_SHM  [READY]\n");
    printf("  [+] DACL Security: Active on all IPC objects\n\n");
    printf("  >> ACCESS KEY : IPC2026SECURE\n");
    printf("  >> DASHBOARD  : http://localhost:8080\n\n");

    HttpServer srv;
    if (!srv.start(8080)) {
        printf("  [FATAL] Cannot bind port 8080. Another instance may be running.\n");
        return 1;
    }

    gLog.add("INFO", "HTTP server listening on 0.0.0.0:8080");
    ShellExecuteA(0, 0, "http://localhost:8080", 0, 0, SW_SHOW);
    srv.run();
    return 0;
}
