# OPREATING_SYSTEM: IPC Framework — C++17 / Windows

> An educational and robust Windows IPC simulator. Demonstrates OS-level communication mechanisms (Pipes, Mailslots, Shared Memory) and secure token authentication with no third-party dependencies.

A lightweight Inter-Process Communication framework using native Windows APIs,
with a web dashboard for live interaction and monitoring.

## Architecture

```
ipc_server.exe  ←→  Browser (http://localhost:8080)
     │
     ├── Named Pipes     (CreateNamedPipe / WriteFile / ReadFile)
     ├── Message Queues  (CreateMailslot — Windows mailslot API)
     ├── Shared Memory   (CreateFileMapping + MapViewOfFile + spinlock)
     └── HTTP Server     (raw Winsock2, no external libs)
```

## Files

| File            | Purpose                                      |
|-----------------|----------------------------------------------|
| `main.cpp`      | Entry point, prints master token, starts HTTP |
| `ipc_core.h`    | Pipe, Queue, SharedMemory, Auth, Crypto, Log |
| `http_server.h` | Winsock2 HTTP server + REST API router        |
| `dashboard.html`| Web UI — served at http://localhost:8080      |
| `CMakeLists.txt`| CMake build config                           |

## Build (Visual Studio / CMake)

```bash
# Prerequisites: Visual Studio 2019+ with C++ workload, CMake 3.16+

mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# OR with Ninja:
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
```

## Build (Direct cl.exe — no CMake needed)

```bat
cl /std:c++17 /EHsc /O2 main.cpp /link ws2_32.lib /out:ipc_server.exe
copy dashboard.html .
```

## Run

```bat
ipc_server.exe
```

Console output:
```
  ╔══════════════════════════════════════════╗
  ║   IPC Framework Server  v1.0             ║
  ║   Pipes | Message Queues | Shared Memory ║
  ╚══════════════════════════════════════════╝

  [*] Master Token : AbCdEfGhIjKlMnOp
  [*] Dashboard    : http://localhost:8080
```

Open browser → http://localhost:8080

## Using the Dashboard

1. **Auth** — paste the master token from console → click "Issue Session Token"
2. **Init channels** — click Init next to Pipe, Queue, Shared Memory in sidebar
3. **Pipe tab** — type a message, optionally enable encryption, Send / Receive
4. **Queue tab** — enqueue messages with priority, dequeue one at a time
5. **Shared Memory tab** — write data to the shared region, read it back live
6. **Audit Log tab** — all security events, errors, and operations logged

## Security Features

| Feature           | Implementation                          |
|-------------------|-----------------------------------------|
| Token auth        | Random 32-char tokens, master-issued    |
| Encryption        | XOR cipher with shared key (swappable)  |
| Spinlock sync     | InterlockedCompareExchange on SHM       |
| ACL enforcement   | Every IPC op checks token validity      |
| Audit log         | All ops logged with timestamp + level   |
| Token revocation  | Instant via dashboard                   |

## Extending

- **Swap encryption**: Replace `Crypto::xorEncrypt` with AES (add `bcrypt.lib`)
- **Add POSIX**: The `PipeChannel`/`SharedMemory` classes can be ported with `#ifdef`
- **Multi-client pipes**: Change `nMaxInstances` in `CreateNamedPipe` and loop accepts
- **Priority queue**: Replace mailslot with a sorted `std::priority_queue` + mutex

## Dependencies

- Windows SDK (any modern version)
- C++17 compiler (MSVC 2019+ / Clang-cl)
- No third-party libraries
