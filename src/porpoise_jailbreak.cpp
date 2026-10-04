/* Porpoise - asking the HEN to free Porpoise from the app sandbox.
 * Copyright (C) 2026 Ruben (Project Porpoise)
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Porpoise needs to see the whole console: /data for its own folder and the
 * player's games, USB drives, and so on. Most setups start it that way
 * already (etaHEN or the launcher frees each homebrew app). Where it starts
 * inside the sandbox, /data is missing or empty and the folder browser shows
 * only a few folders; Porpoise then asks the HEN itself, the way PS5SX2 does
 * (ps5/coreorbis/orbis-shims/ProsperoHenJailbreak.cpp and main-boot.cpp in
 * PS5SX2, GPL-3.0-or-later; this is a port of its approach):
 *
 *   1. etaHEN / OnionHEN / Lapy JB Daemon's request file: {"PID":<pid>}
 *      written to /download0/etahen_jailbreak (atomically, through a .tmp).
 *      The HEN or daemon consumes it and frees the process. etaHEN/OnionHEN
 *      need the title ID on their app jailbreak list; Lapy JB Daemon handles
 *      any app automatically.
 *
 *      Lapy JB Daemon note: the daemon's getHijacker call can lose a timing
 *      race on the first try (the process isn't visible to the kernel proc
 *      scanner yet). The daemon deletes the request file regardless of
 *      whether the jailbreak succeeded, so a consumed file does not prove
 *      success. Porpoise retries the whole request up to three times,
 *      checking uid and /data access after each round.
 *
 *   2. Failing that, the legacy command servers on 127.0.0.1 (etaHEN 9028,
 *      the SharpProspero unjail daemon 9069): command 5, jailbreak this PID.
 *
 * Every step goes to trace.txt. Nothing here runs when /data is reachable. */
#include "porpoise_jailbreak.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <initializer_list>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "trace.hpp"

extern "C" int sceKernelUsleep(unsigned microseconds);

namespace porpoise::jailbreak
{
bool data_reachable();

namespace
{
constexpr char kRequest[] = "/download0/etahen_jailbreak";
constexpr char kStaged[] = "/download0/etahen_jailbreak.tmp";
/* Maximum attempts for the file-based jailbreak. Lapy JB Daemon can lose a
 * timing race on the first try (getHijacker fails when the process is too
 * new); a second or third attempt usually wins. */
constexpr int kMaxFileAttempts = 3;

void note(const char *fmt, int a = 0, int b = 0, int c = 0)
{
    char line[200];
    std::snprintf(line, sizeof line, fmt, a, b, c);
    ps5::debug::mark(line);
}

/* Whether the process has been jailbroken (uid 0 = root). This catches the
 * case where Lapy JB Daemon consumed the request file but getHijacker lost
 * the race and the actual credential bump never happened. */
bool is_root() { return geteuid() == 0; }

/* Write the request file and wait for a daemon to pick it up. Returns true
 * only when something consumed the file (the actual jailbreak may still have
 * failed on the daemon's side). */
bool publish_request()
{
    const int pid = int(getpid());
    unlink(kStaged);
    unlink(kRequest);
    const int fd = open(kStaged, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (fd < 0)
    {
        note("jailbreak: request file can't be made (errno %d)", errno);
        return false;
    }
    fchmod(fd, 0666);
    char body[32];
    const int n = std::snprintf(body, sizeof body, "{\"PID\":%d}\n", pid);
    const bool written = write(fd, body, std::size_t(n)) == n && fsync(fd) == 0;
    close(fd);
    if (!written || rename(kStaged, kRequest) != 0)
    {
        unlink(kStaged);
        note("jailbreak: request file not published (errno %d)", errno);
        return false;
    }
    /* Up to 4 s for the daemon to take the file. */
    int polls = 0;
    while (access(kRequest, F_OK) == 0 && polls < 240)
    {
        sceKernelUsleep(16667);
        ++polls;
    }
    if (access(kRequest, F_OK) == 0)
    {
        unlink(kRequest);
        note("jailbreak: no daemon took the request");
        return false;
    }
    note("jailbreak: request taken after %d polls", polls);
    return true;
}

/* Full file-based jailbreak cycle with retries. Handles the Lapy JB Daemon
 * timing race: the daemon always deletes the file even when getHijacker
 * fails, so "file consumed" does not mean "jailbreak done." We verify with
 * is_root() and data_reachable() after each attempt and retry if needed. */
bool request_file()
{
    for (int attempt = 1; attempt <= kMaxFileAttempts; ++attempt)
    {
        note("jailbreak: file attempt %d/%d", attempt, kMaxFileAttempts);

        /* Small delay before retries so the daemon's proc scanner can catch
         * up. The first attempt goes immediately. */
        if (attempt > 1)
            sceKernelUsleep(500000); /* 500 ms between retries */

        if (!publish_request())
        {
            /* No daemon consumed the file. On the first attempt this might
             * mean etaHEN isn't loaded; on retries it means the daemon went
             * away. Either way, fall through to the port-based path. */
            if (attempt == 1)
                note("jailbreak: file not consumed (is PPSA99764 on the HEN's "
                     "list, or is Lapy JB Daemon running?)");
            break;
        }

        /* The file was consumed. Give the daemon up to 2 s to finish the
         * credential bump and sandbox escape. */
        int grace = 0;
        while (!is_root() && grace < 120)
        {
            sceKernelUsleep(16667);
            ++grace;
        }

        if (is_root())
        {
            /* Credential bump confirmed. Wait a little more for the sandbox
             * escape (fd_rdir/fd_jdir = rootvnode) to take effect. */
            grace = 0;
            while (!data_reachable() && grace < 120)
            {
                sceKernelUsleep(16667);
                ++grace;
            }
            note("jailbreak: confirmed root after attempt %d; uid=%d", attempt, int(geteuid()));
            return true;
        }

        /* The daemon consumed the file but the jailbreak didn't stick
         * (Lapy JB Daemon timing race). Try again. */
        note("jailbreak: attempt %d consumed but uid still %d; retrying", attempt, int(geteuid()));
    }

    /* Final fallback: even without uid 0, check whether /data is reachable.
     * Some HEN configurations grant filesystem access without changing uid. */
    if (data_reachable())
    {
        note("jailbreak: uid is %d but /data is reachable", int(geteuid()));
        return true;
    }
    return false;
}

/* The legacy command servers: magic, command 5 (jailbreak), the PID. */
bool request_port()
{
    struct Command
    {
        int magic;
        int cmd;
        int pid;
        int ret;
        char msg1[0x500];
        char msg2[0x500];
    } cmd{};
    for (int port : {9028, 9069})
    {
        cmd = Command{};
        cmd.magic = int(0xDEADBEEF);
        cmd.cmd = 5;
        cmd.pid = int(getpid());
        cmd.ret = -1337;
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return false;
        /* A server that takes the connection but never answers mustn't hold
         * Porpoise's start: 2 s each way. */
        timeval limit{};
        limit.tv_sec = 2;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(std::uint16_t(port));
        sa.sin_addr.s_addr = htonl(0x7F000001);
        if (connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof sa) != 0)
        {
            close(fd);
            note("jailbreak: nothing on port %d", port);
            continue;
        }
        const bool sent = send(fd, &cmd, sizeof cmd, 0) == ssize_t(sizeof cmd);
        int got = 0;
        while (sent && got < int(sizeof cmd))
        {
            const ssize_t r = recv(fd, reinterpret_cast<char *>(&cmd) + got, sizeof cmd - std::size_t(got), 0);
            if (r <= 0)
                break;
            got += int(r);
        }
        close(fd);
        note("jailbreak: port %d answered %d (%d bytes)", port, cmd.ret, got);
        if (sent && got == int(sizeof cmd) && cmd.ret == 0)
            return true;
    }
    return false;
}
} // namespace

bool data_reachable()
{
    struct stat st;
    if (stat("/data", &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    mkdir("/data/porpoise", 0777);
    const char probe[] = "/data/porpoise/.write-test";
    const int fd = open(probe, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0)
        return false;
    close(fd);
    unlink(probe);
    return true;
}

bool ensure()
{
    if (data_reachable())
        return true;
    note("jailbreak: /data isn't reachable (uid %d); asking the HEN / daemon", int(geteuid()));
    if (!request_file())
        request_port();
    /* One more check after everything has been tried. */
    if (!data_reachable())
    {
        /* Last resort: a short sleep then recheck. Some daemons finish the
         * sandbox escape asynchronously after the credential bump. */
        sceKernelUsleep(500000);
    }
    const bool ok = data_reachable();
    note(ok ? "jailbreak: /data is reachable now (uid %d)"
            : "jailbreak: still sandboxed (uid %d); using the app's own folder",
         int(geteuid()));
    return ok;
}
} // namespace porpoise::jailbreak
