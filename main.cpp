#include "http_server.h"
#include <iostream>
#include <cstdio>
#include <shellapi.h>

int main() {
    // Console visual banner
    printf("\n");
    printf("  ======================================================\n");
    printf("     IPC FRAMEWORK NODE — C++17 / Native Windows API    \n");
    printf("  ======================================================\n");
    printf("   [+] Named Pipes   (Threaded listener, Duplex)\n");
    printf("   [+] Mailslot      (Message Queues, Priority)\n");
    printf("   [+] Shared Memory (File Mapping, Spinlock sync)\n");
    printf("  ------------------------------------------------------\n\n");

    // Secure generation of master token
    gMasterToken = Crypto::generateToken(16);
    
    // Save to file for easy copy/paste and automated testing scripts
    FILE* tf = fopen("token.txt", "w");
    if (tf) {
        fprintf(tf, "%s", gMasterToken.c_str());
        fclose(tf);
    }

    printf("  >> MASTER TOKEN : %s\n", gMasterToken.c_str());
    printf("     (Also saved to token.txt in working directory)\n\n");
    printf("  >> DASHBOARD    : http://localhost:8080\n");
    printf("     Starting HTTP API Server...\n");

    gLog.add("INFO", "IPC Framework Boot Sequence Started");
    gLog.add("SECURITY", "Master token generated (16-byte cryptographically secure)");

    HttpServer srv;
    if (!srv.start(8080)) {
        printf("\n  [FATAL] Failed to bind port 8080. Is another instance running?\n");
        return 1;
    }

    // Auto-launch browser
    gLog.add("INFO", "Launching browser UI -> http://localhost:8080");
    ShellExecuteA(0, 0, "http://localhost:8080", 0, 0, SW_SHOW);

    srv.run();
    return 0;
}
