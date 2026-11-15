#pragma once

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <share.h>

// Shared by startup and hook callbacks. Inline state denotes one logger per DLL,
// rather than a separate log path/lock in each translation unit.
namespace PatchLogging {
    inline std::wstring logPath;
    inline SRWLOCK logLock = SRWLOCK_INIT;
    inline bool verboseLogging = false;

    // Startup resets the previous session before configuration is loaded, so a
    // malformed INI still leaves a diagnostic. The DLL directory is the anchor:
    // the preservation loader can attach this patch from outside the game's working directory.
    inline void BeginSession(const std::wstring& path) {
        logPath = path;
        if (FILE* file = _wfsopen(logPath.c_str(), L"w", _SH_DENYNO)) {
            fclose(file);
        }
    }

    // Callbacks can log concurrently. Serialize the size check and write so the
    // session cap remains bounded even during repeated failures. Closing per line
    // preserves completed diagnostics on a crash; callers must not log credentials,
    // HTTP paths/queries, public-key contents or captured image bytes.
    inline void Log(const char* format, ...) {
        AcquireSRWLockExclusive(&logLock);
        FILE* file = _wfsopen(logPath.c_str(), L"a", _SH_DENYNO);
        if (file) {
            _fseeki64(file, 0, SEEK_END);
        }
        if (file && _ftelli64(file) < 1024 * 1024) {
            char line[4096]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(line, sizeof(line), _TRUNCATE, format, args);
            va_end(args);
            const auto remaining = static_cast<size_t>(1024 * 1024 - _ftelli64(file));
            const auto length = (std::min)(strlen(line), remaining);
            fwrite(line, 1, length, file);
            if (remaining > length) {
                fputc('\n', file);
            }
        }
        if (file) {
            fclose(file);
        }
        ReleaseSRWLockExclusive(&logLock);
    }
    // Routine hot-path messages are opt-in. Startup sets this flag before hooks
    // become active and does not reload it while callbacks are running.
    template <typename... Args> inline void LogVerbose(const char* format, Args... args) {
        if (verboseLogging) {
            Log(format, args...);
        }
    }

}
