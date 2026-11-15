// PreserveLoader.dll -- Rec Room 2026 preservation proxy loader.
//
// Rec Room statically imports exactly one module, "Referee.dll" (the Themida
// protector; the client links a single gated symbol, "jjiEVn"). A proxy under
// that name is an ordinary first-class way in: the game binds itself to this
// module at process-init time, no remote threads, no cross-process memory
// writes, no suspended threads.
//
// What this loader does:
//   1. DllMain installs a vectored exception handler BEFORE loading the real
//      protector (preserve\Referee.dll) with LoadLibraryW, exactly as the client
//      would have loaded it. The protector's own DllMain runs in the normal
//      import phase and decrypts the client's .text.
//   2. The protector's DllMain faults while reading the retired service's
//      arena: the faulting instruction is "mov eax,[r8]" at Referee+0x69839D
//      with r8 = 0x100040, i.e. a NULL arena pointer plus the second queue's
//      offset (+0x100040). The handler builds the same 64 MiB local arena the
//      out-of-process publisher this loader replaces used to build, repoints r8
//      protector. The protector's DllMain never returns before the loader can
//      ask for its base, so the handler recovers the base from the faulting
//      module's PE header instead of from a module-list lookup.
//   3. jjiEVn is exported by this loader and forwards to the protector's own
//      jjiEVn, resolved lazily (the protector's export table only becomes
//      usable after its unpack finishes).
//   4. GetPreserveProtector() is exported so 2026patch.dll can find the
//      protector's load base even though "Referee.dll" in the module list is
//      this proxy.
//   5. A watcher thread waits for GameAssembly.dll to finish loading, then loads
//      EVERY *.dll found in preserve\modules\ -- the folder IS the mod system.
//      Load order is alphabetical (sort by filename), so modules that need to
//      run first use a numeric prefix (e.g. 0000-core.dll). 2026patch.dll lives
//      in that folder too. A module that fails to load is logged and skipped.
//
// Layout after Install-PreserveLoader.bat:
//   Referee.dll                    <- this loader (jjiEVn export)
//   preserve\Referee.dll           <- the real protector, untouched
//   preserve\modules\*.dll         <- the mods (2026patch.dll among them)
//
// Revert at any time with Restore-RefereeProtector.bat.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <string>
#include <vector>
#include <algorithm>

extern "C" unsigned long long g_realXNfn = 0; // protector's jjiEVn export
static uintptr_t g_protectorBase = 0;
static uintptr_t g_arena = 0;
static LONG g_publishBusy = 0;

static void Log(const char* fmt, ...);
static void GetModuleDir(HMODULE module, wchar_t* out, size_t outCount);

// Retired-service arena seam (see AGENTS.md "Arena seam and Referee
// bootstrap"). The protector reads a NULL arena pointer at Referee+0x69839D and
// faults; we publish the same local arena that code path used to build.
static const uintptr_t kArenaSlotOffset = 0x6C10858; // Referee+ArenaSlot
static const uintptr_t kArenaStride = 0x1500030ull;
static const uintptr_t kArenaSize = 0x4000000ull; // 64 MiB
static const uintptr_t kQueueOffsets[2] = {0xA0, 0x100040};
static const uint32_t kQueueLengths[2] = {0x80000, 0x1000000};
static const uintptr_t kBootstrapOffset = 0x69839D; // Referee+BootstrapInstruction

// Build the arena the client expects: three channel descriptors at
// stride 0x1500030, each with two length-prefixed double-buffered queues.
// Both capacities are (length - 0x1C) / 2; a zero length underflows and
// produces invalid second-buffer pointers and later access violations.
// There is no service consumer; normal full-queue handling remains intact.
static uintptr_t BuildArena() {
    uintptr_t arena = (uintptr_t)VirtualAlloc(nullptr, kArenaSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!arena) {
        Log("arena: VirtualAlloc failed (error %lu)", GetLastError());
        return 0;
    }
    for (unsigned channel = 0; channel < 3; ++channel) {
        uintptr_t seg = arena + channel * kArenaStride;
        for (unsigned q = 0; q < 2; ++q) {
            uint32_t length = kQueueLengths[q];
            uint32_t capacity = (length - 0x1C) / 2;
            uint32_t header[8] = {length, 0, 0, capacity, 0, 0, capacity, 0};
            memcpy((void*)(seg + kQueueOffsets[q]), header, sizeof(header));
        }
    }
    return arena;
}

// Publish the arena into the protector's pointer slot. The slot holds a
// pointer to a pointer; the retired service used to write the arena address there.
static void PublishArenaAt(uintptr_t base) {
    uintptr_t slot = base + kArenaSlotOffset;
    uintptr_t pointer = *(uintptr_t*)slot;
    if (!pointer) {
        return; // the protector has not published its arena pointer yet
    }
    uintptr_t arena = g_arena;
    if (!arena) {
        arena = BuildArena();
        if (!arena) {
            return;
        }
        g_arena = arena;
    }
    *(uintptr_t*)pointer = arena;
}

// Recover the protector's image base from a faulting address. The protector is
// loaded at its preferred base and its PE header is intact, so the base can be
// recovered even while the loader lock is held and LoadLibrary has not returned
// yet. The preferred base is read from the protector file before it is loaded.
static uintptr_t g_expectedBase = 0;

// Read an image's preferred base from its PE headers.
static uintptr_t ReadImageBaseFromFile(const wchar_t* path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    LARGE_INTEGER size = {};
    GetFileSizeEx(file, &size);
    if (size.QuadPart < 0x1000) {
        CloseHandle(file);
        return 0;
    }
    unsigned char head[0x1000] = {};
    DWORD got = 0;
    if (!ReadFile(file, head, sizeof(head), &got, nullptr) || got < 0x40) {
        CloseHandle(file);
        return 0;
    }
    CloseHandle(file);
    if (head[0] != 'M' || head[1] != 'Z') {
        return 0;
    }
    DWORD e_lfanew = *(DWORD*)(head + 0x3C);
    if (e_lfanew + 0x60 > got) {
        return 0;
    }
    if (head[e_lfanew] != 'P' || head[e_lfanew + 1] != 'E') {
        return 0;
    }
    DWORD magic = *(WORD*)(head + e_lfanew + 24);
    uintptr_t base;
    if (magic == 0x20B) {
        base = *(uintptr_t*)(head + e_lfanew + 24 + 24);
    } else if (magic == 0x10B) {
        base = *(uint32_t*)(head + e_lfanew + 24 + 28);
    } else {
        return 0;
    }
    return base;
}

// Confirm a candidate base is a loaded PE image whose size covers the fault.
static bool LooksLikeImageBase(uintptr_t base, uintptr_t fault) {
    if (!base) {
        return false;
    }
    const unsigned char* p = (const unsigned char*)base;
    if (p[0] != 'M' || p[1] != 'Z') {
        return false;
    }
    DWORD e_lfanew = *(DWORD*)(p + 0x3C);
    if (!e_lfanew || e_lfanew >= 0x1000) {
        return false;
    }
    if (p[e_lfanew] != 'P' || p[e_lfanew + 1] != 'E') {
        return false;
    }
    DWORD magic = *(WORD*)(p + e_lfanew + 24);
    uintptr_t sizeOfImage =
        (magic == 0x20B) ? *(uint32_t*)(p + e_lfanew + 24 + 56) : *(uint32_t*)(p + e_lfanew + 24 + 56);
    if (base + sizeOfImage > fault) {
        return true;
    }
    return false;
}

static uintptr_t BaseFromFault(uintptr_t fault) {
    if (LooksLikeImageBase(g_expectedBase, fault)) {
        return g_expectedBase;
    }
    // Fall back to walking down to the image header.
    uintptr_t base = fault & ~0xFFFFFull;
    for (int i = 0; i < 0x2000; ++i, base -= 0x1000) {
        if (base < 0x10000) {
            break;
        }
        if (LooksLikeImageBase(base, fault)) {
            return base;
        }
    }
    return 0;
}

// In-process replica of the out-of-process arena publish that used to ship with
// measured instruction bytes to appear at Referee+BootstrapInstruction and for
// the pointer slot to be initialized, then writes the arena BEFORE the
// protector's first read. The module list is populated before the protector's
// DllMain runs, so an external watcher gets the whole of that DllMain as
// head start; this thread gets the same head start because it starts before
// LoadLibrary returns.
// The log file is opened once and kept open. A vectored handler must not
// resolve a path or use the CRT, so it writes through this handle directly.
static HANDLE g_logHandle = INVALID_HANDLE_VALUE;

// =================================================================================================
// CACHED STALE OFFSETS
//
// The protector builds arena addresses as "arena base + offset" and caches them. Its
// first arena read happens after it has already cached a batch of them, and because the
// base was still NULL those cached values are the bare offsets. The external watcher
// avoids this by publishing the arena before the protector's DllMain reads anything.
//
// In-process we cannot run concurrently with the protector's DllMain (the loader lock
// keeps a second thread from starting), so the first read is repaired by the exception
// handler instead. Repairing the register fixes that one access, but the protector keeps
// re-reading the same cached copies, which produced thousands of faults per site.
//
// The fix is to rewrite the cached copies in place: every quadword in the protector's
// writable heap that holds a stale offset becomes "arena + offset". The values are
// distinctive (arena offsets, not lengths or counters), and the scan deliberately skips
// image-backed memory so no code or read-only data can be touched.
// =================================================================================================

static constexpr LONG kMaxCachedOffsets = 64;
// The stored value is the offset plus one, so zero means "slot unused".
static volatile LONG g_cachedOffsets[kMaxCachedOffsets];
static volatile LONG g_cachedOffsetCount = 0;

static void QueueCachedOffset(uintptr_t offset) {
    if (!offset || offset >= kArenaSize) {
        return;
    }
    const LONG value = static_cast<LONG>(offset + 1);
    for (LONG i = 0; i < g_cachedOffsetCount; ++i) {
        if (g_cachedOffsets[i] == value) {
            return;
        }
    }
    for (LONG i = 0; i < kMaxCachedOffsets; ++i) {
        LONG expected = 0;
        if (InterlockedCompareExchange(&g_cachedOffsets[i], value, expected) == expected) {
            InterlockedIncrement(&g_cachedOffsetCount);
            return;
        }
    }
}

// Scan one chunk for cached stale offsets and rewrite them. Kept free of C++
// objects so that SEH can be used: the scan reads memory the protector is
// actively using, so a concurrent unmap or protection change is possible and
// one bad chunk must not end the process.
static uintptr_t g_scanArena = 0;
static size_t g_scanPendingCount = 0;

static unsigned ScanChunkForStaleOffsets(LPVOID address, size_t length, unsigned char* buffer) {
    unsigned patched = 0;
    __try {
        // A direct copy: this is the same process, so the kernel path of
        // ReadProcessMemory only adds cost to a scan that runs while the
        // protector is faulting.
        memcpy(buffer, address, length);
        bool changed = false;
        for (size_t i = 0; i + 8 <= length; i += 8) {
            uintptr_t value = 0;
            memcpy(&value, buffer + i, sizeof(value));
            if (!value) {
                continue;
            }

            // Only rewrite a value that is part of the protector's pointer
            // TABLE. The table holds several stale arena offsets next to each
            // other, so a candidate is accepted only when one of its
            // neighbours is a stale offset too. A coincidental value in the
            // game's own heap has no such neighbour, and rewriting it would
            // corrupt the game.
            bool inTable = false;
            for (int step = 1; step <= 8 && !inTable; ++step) {
                const size_t neighbours[2] = {i >= step * 8 ? i - step * 8 : (size_t)-1,
                                              i + step * 8 < length ? i + step * 8 : (size_t)-1};
                for (size_t n = 0; n < 2 && !inTable; ++n) {
                    if (neighbours[n] == (size_t)-1) {
                        continue;
                    }
                    uintptr_t other = 0;
                    memcpy(&other, buffer + neighbours[n], sizeof(other));
                    if (!other) {
                        continue;
                    }
                    for (size_t p = 0; p < g_scanPendingCount; ++p) {
                        const uintptr_t stale = static_cast<uintptr_t>(g_cachedOffsets[p]) - 1;
                        if (other == stale || other == g_scanArena + stale) {
                            inTable = true;
                            break;
                        }
                    }
                }
            }
            if (!inTable) {
                continue;
            }

            for (size_t p = 0; p < g_scanPendingCount; ++p) {
                const uintptr_t stale = static_cast<uintptr_t>(g_cachedOffsets[p]) - 1;
                if (value != stale) {
                    continue;
                }
                const uintptr_t replacement = g_scanArena + stale;
                memcpy(buffer + i, &replacement, sizeof(replacement));
                ++patched;
                changed = true;
                break;
            }
        }
        if (changed) {
            memcpy(address, buffer, length);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return patched;
}

// Rewrite every quadword in the protector's writable memory that holds a stale offset.
static DWORD WINAPI CachedOffsetPatchThread(LPVOID) {
    struct Region {
        uintptr_t base;
        size_t size;
    };
    std::vector<Region> regions;
    const size_t chunk = 4 * 1024 * 1024;
    unsigned char* buffer =
        (unsigned char*)VirtualAlloc(nullptr, chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LONG handled = 0;
    ULONGLONG lastPass = 0;
    for (;;) {
        const LONG count = g_cachedOffsetCount;
        size_t pendingCount = 0;
        while (handled < count && pendingCount < kMaxCachedOffsets) {
            const LONG value = g_cachedOffsets[handled];
            ++handled;
            if (value <= 0) {
                continue;
            }
            ++pendingCount;
        }
        // Scan again even without new offsets: the protector keeps producing
        // fresh copies of the stale pointers as it runs, and the region list
        // itself changes as it allocates.
        const ULONGLONG now = GetTickCount64();
        const bool due = (now - lastPass) > 3000;
        if (!pendingCount && !due) {
            Sleep(50);
            continue;
        }
        lastPass = now;

        // Rebuild the region list: the protector allocates while it runs and the
        // cached pointers turn up in different places over time.
        regions.clear();
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t address = 0;
        while (address < 0x7FFFFFFFFFFF && regions.size() < 8192) {
            if (!VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
                break;
            }
            if (!mbi.RegionSize) {
                break;
            }
            const bool writable =
                (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) != 0;
            // A guard page raises STATUS_GUARD_PAGE_VIOLATION when it is read,
            // which would end this thread (and with it the process).
            const bool guarded = (mbi.Protect & PAGE_GUARD) != 0;
            const bool inaccessible = (mbi.Protect & PAGE_NOACCESS) != 0;
            if (mbi.State == MEM_COMMIT && writable && !guarded && !inaccessible) {
                regions.push_back({(uintptr_t)mbi.BaseAddress, (size_t)mbi.RegionSize});
            }
            address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }
        size_t totalBytes = 0;
        for (const Region& region : regions) {
            totalBytes += region.size;
        }

        const uintptr_t arena = g_arena;
        if (!arena || !buffer || !g_cachedOffsetCount) {
            continue;
        }

        unsigned patched = 0;
        g_scanArena = arena;
        g_scanPendingCount =
            g_cachedOffsetCount > kMaxCachedOffsets ? kMaxCachedOffsets : g_cachedOffsetCount;
        for (size_t r = 0; r < regions.size(); ++r) {
            const Region& region = regions[r];
            for (size_t start = 0; start < region.size; start += chunk) {
                const size_t length = (region.size - start < chunk) ? region.size - start : chunk;
                patched += ScanChunkForStaleOffsets((LPVOID)(region.base + start), length, buffer);
            }
        }
        if (patched) {
            Log("cached-offset patcher: %u cached pointers rewritten across %zu regions (%zu bytes)", patched,
                regions.size(), totalBytes);
        }
    }
    return 0;
}

// Append raw bytes to the log. No CRT, no allocation: safe inside a vectored
// exception handler.
static void AppendRaw(const char* text, size_t length) {
    if (g_logHandle == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    WriteFile(g_logHandle, text, static_cast<DWORD>(length), &written, nullptr);
}

// Format a 64-bit value as hex without the CRT.
static size_t FormatHex(char* out, size_t capacity, unsigned long long value) {
    static const char kDigits[] = "0123456789ABCDEF";
    char buffer[16];
    size_t count = 0;
    do {
        buffer[count++] = kDigits[value & 0xF];
        value >>= 4;
    } while (value && count < sizeof(buffer));
    size_t used = 0;
    while (count && used + 1 < capacity) {
        out[used++] = buffer[--count];
    }
    return used;
}

// Write one compact fault line straight to the log file. The ring buffer
// below is the richer channel; this line exists because a fatal fault can end
// the process before anything drains that ring.
//
// A fault site can repeat thousands of times, and one file write per fault is
// slow enough to starve the threads that repair the damage. Each site is
// therefore reported a few times and then counted only.
static LONG g_faultSiteSeen[512];

static bool ShouldReportFault(uintptr_t rip) {
    const size_t slot = (rip >> 4) & 511u;
    LONG* counter = &g_faultSiteSeen[slot];
    const LONG count = InterlockedIncrement(counter);
    return count <= 3;
}

// WriteFaultLine was the first diagnostic: one raw line per fault, straight to the
// file. It was too slow inside a vectored handler and was replaced by the ring buffer
// plus the fault log thread. The code is gone; keep it gone.

// Defined with the fault recorder further down; the handler only copies into
// the ring buffer.
static void RecordFault(const char* tag, EXCEPTION_POINTERS* ep);

// Defined with the fault recorder further down.
static LONG HandleArenaWatchpoint(EXCEPTION_POINTERS* ep);

// Defined with the fault recorder further down.
static LONG CALLBACK CrashWatch(EXCEPTION_POINTERS* ep);

// =================================================================================================
// INSTRUCTION DECODER
//
// To repair a stale arena pointer the handler has to know WHICH register supplied the
// low effective address. Guessing from the register values alone is wrong: the faulting
// address is "stale base + index", so both registers look plausible. Decoding the
// instruction's ModRM/SIB byte names the base register exactly.
//
// Only the operand shape is decoded, not the instruction: the question is never "what
// does this instruction do" but "which register is the base of its memory operand".
// =================================================================================================

struct MemoryOperand {
    int base = -1;  // register number, or -1 when there is none
    int index = -1; // register number, or -1 when there is none
    int scale = 1;
    long long displacement = 0;
    bool valid = false;
};

// Register numbers use the x64 encoding: 0=rax 1=rcx 2=rdx 3=rbx 4=rsp 5=rbp
// 6=rsi 7=rdi 8..15=r8..r15.
static DWORD64* RegisterByNumber(CONTEXT* context, int number) {
    switch (number) {
    case 0:
        return &context->Rax;
    case 1:
        return &context->Rcx;
    case 2:
        return &context->Rdx;
    case 3:
        return &context->Rbx;
    case 4:
        return &context->Rsp;
    case 5:
        return &context->Rbp;
    case 6:
        return &context->Rsi;
    case 7:
        return &context->Rdi;
    case 8:
        return &context->R8;
    case 9:
        return &context->R9;
    case 10:
        return &context->R10;
    case 11:
        return &context->R11;
    case 12:
        return &context->R12;
    case 13:
        return &context->R13;
    case 14:
        return &context->R14;
    case 15:
        return &context->R15;
    default:
        return nullptr;
    }
}

static bool OpcodeHasModRM(unsigned char opcode) {
    if (opcode >= 0x50 && opcode <= 0x6F) {
        return false; // push/pop/ins/outs
    }
    if (opcode >= 0x70 && opcode <= 0x7F) {
        return false; // jcc rel8
    }
    if (opcode >= 0x90 && opcode <= 0x9F) {
        return false; // xchg/callf/jmpf
    }
    if (opcode >= 0xA0 && opcode <= 0xBF) {
        return false; // mov moffs, test imm, string ops
    }
    if (opcode == 0xC2 || opcode == 0xC3) {
        return false; // ret
    }
    if (opcode >= 0xC8 && opcode <= 0xCF) {
        return false; // enter/leave/iret
    }
    if (opcode == 0xD4 || opcode == 0xD5) {
        return false; // aam/aad
    }
    if (opcode == 0xD6 || opcode == 0xD7) {
        return false; // xlat, salc
    }
    if (opcode >= 0xE0 && opcode <= 0xEF) {
        return false; // loop/jcc/call/jmp
    }
    if (opcode == 0xF1 || opcode == 0xF4 || opcode == 0xF5) {
        return false;
    }
    if (opcode >= 0xF8 && opcode <= 0xFD) {
        return false;
    }
    if (opcode <= 0x3F && (opcode & 7) >= 6) {
        return false; // the six/seven forms
    }
    return true;
}

// Decode the memory operand of the instruction at `code`. Returns false when the
// instruction has no memory operand or cannot be decoded.
static bool DecodeMemoryOperand(const unsigned char* code, size_t length, MemoryOperand& operand) {
    operand = MemoryOperand{};
    if (!code || length < 2) {
        return false;
    }

    size_t i = 0;
    int rex = 0;
    while (i < length) {
        const unsigned char b = code[i];
        const bool prefix = b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E ||
                            b == 0x26 || b == 0x64 || b == 0x65 || b == 0x66;
        if (!prefix) {
            break;
        }
        ++i;
    }
    if (i < length && code[i] >= 0x40 && code[i] <= 0x4F) {
        rex = code[i];
        ++i;
    }
    if (i >= length) {
        return false;
    }

    const unsigned char opcode = code[i++];
    if (opcode == 0x0F) {
        if (i >= length) {
            return false;
        }
        const unsigned char second = code[i++];
        if (second >= 0x80 && second <= 0x8F) {
            return false; // jcc rel32 has no ModRM
        }
    } else if (opcode >= 0x40 && opcode <= 0x4F) {
        return false; // inc/dec r64
    } else if (!OpcodeHasModRM(opcode)) {
        return false;
    }
    if (i >= length) {
        return false;
    }

    const unsigned char modrm = code[i++];
    const int mod = modrm >> 6;
    const int rm = modrm & 7;
    if (mod == 3) {
        return false; // register operand
    }

    if (rm == 4) {
        if (i >= length) {
            return false;
        }
        const unsigned char sib = code[i++];
        operand.scale = 1 << ((sib >> 6) & 3);
        const int index = (sib >> 3) & 7;
        const int base = sib & 7;
        if (!(index == 4 && !(rex & 0x02))) {
            operand.index = index | ((rex & 0x02) ? 8 : 0);
        }
        if (base == 5 && mod == 0) {
            // No base register: the address is disp32.
            if (i + 4 > length) {
                return false;
            }
            int32_t disp = 0;
            memcpy(&disp, code + i, 4);
            operand.displacement = disp;
            i += 4;
            operand.valid = true;
            return true;
        }
        operand.base = base | ((rex & 0x01) ? 8 : 0);
    } else {
        if (mod == 0 && rm == 5) {
            // RIP-relative: the base is the instruction pointer, not a register.
            return false;
        }
        operand.base = rm | ((rex & 0x01) ? 8 : 0);
    }

    if (mod == 1) {
        if (i >= length) {
            return false;
        }
        operand.displacement = static_cast<signed char>(code[i]);
        ++i;
    } else if (mod == 2) {
        if (i + 4 > length) {
            return false;
        }
        int32_t disp = 0;
        memcpy(&disp, code + i, 4);
        operand.displacement = disp;
        i += 4;
    }
    operand.valid = true;
    return true;
}

// Vectored handler: the protector faults reading a NULL arena during its
// DllMain. Build the arena, relocate the stale NULL-derived register and
// resume. More than one register can retain NULL+queueOffset after the first
// read, so later low-address arena faults are repaired by the same rule.
static LONG CALLBACK ArenaFaultHandler(EXCEPTION_POINTERS* ep) {
    // The watchpoint fires on the protector's store into the arena slot, before
    // it reads its own frame. Handle it first.
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        const LONG result = HandleArenaWatchpoint(ep);
        if (result != EXCEPTION_CONTINUE_SEARCH) {
            return result;
        }
    }
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    uintptr_t fault = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
    uintptr_t target = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
    uintptr_t base = g_protectorBase ? g_protectorBase : BaseFromFault(fault);
    if (!base) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    g_protectorBase = base;

    // Only repair faults raised by the measured protector image. This must not
    // become a broad process-wide access-violation suppressor.
    if (fault < base || fault >= base + 0x88A4000ull) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // The measured first instruction is 41 8B 00 (mov eax, [r8]); r8 holds the
    // arena pointer plus a queue offset, and the arena pointer itself is NULL.
    const uintptr_t bootVa = base + kBootstrapOffset;
    if (target < 0x20 || target >= kArenaSize) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uintptr_t arena = 0;
    if (_InterlockedCompareExchange(&g_publishBusy, 1, 0) != 0) {
        // Another thread is publishing. The arena already exists by now, so the
        // relocation can still be done; only the one-time build needs the lock.
        arena = g_arena;
        if (!arena) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    } else {
        arena = g_arena;
        if (!arena) {
            arena = BuildArena();
            if (!arena) {
                _InterlockedExchange(&g_publishBusy, 0);
                return EXCEPTION_CONTINUE_SEARCH;
            }
            g_arena = arena;
        }
        // Publish into the protector's slot if it is already initialized.
        PublishArenaAt(base);
    }
    // Relocate whichever GPR supplied the low effective address.
    //
    // The protector computes arena addresses as "arena base + offset", and the
    // base was NULL when it cached them, so the cached value is just the offset.
    // Two shapes are measured:
    //   * the register holds the effective address itself (R8 = 0x100040 for the
    //     bootstrap read), and
    //   * the register holds a stale base and an index register supplies the
    //     remainder (R11 = 0x900052 plus RAX = 0x20F2 gives 0x902144).
    // The second shape is why the relocation works on the register that holds
    // the stale base rather than on the register that holds the fault target.
    DWORD64* registers[] = {
        &ep->ContextRecord->Rax, &ep->ContextRecord->Rbx, &ep->ContextRecord->Rcx, &ep->ContextRecord->Rdx,
        &ep->ContextRecord->Rsi, &ep->ContextRecord->Rdi, &ep->ContextRecord->R8,  &ep->ContextRecord->R9,
        &ep->ContextRecord->R10, &ep->ContextRecord->R11, &ep->ContextRecord->R12, &ep->ContextRecord->R13,
        &ep->ContextRecord->R14, &ep->ContextRecord->R15,
    };
    unsigned relocated = 0;
    uintptr_t relocatedFrom = 0;
    for (DWORD64* reg : registers) {
        if (*reg == target) {
            *reg = static_cast<DWORD64>(arena + target);
            ++relocated;
            relocatedFrom = target;
            break;
        }
    }
    if (!relocated) {
        // The faulting address is "stale offset + index", so the register holding
        // the stale offset is the one to repair. Decode the instruction to name
        // the base and index registers exactly: guessing from the register
        // values alone picks the wrong one whenever a genuine small constant
        // takes part in the address too.
        //
        // The protector mutates its own code, so the bytes at the fault site are
        // not necessarily the instruction that executed. The decode is therefore
        // only trusted when the decoded effective address reproduces the fault
        // address exactly.
        unsigned char instruction[16] = {};
        SIZE_T read = 0;
        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)fault, instruction, sizeof(instruction), &read);
        MemoryOperand operand;
        if (read >= 2 && DecodeMemoryOperand(instruction, (size_t)read, operand)) {
            DWORD64* base = operand.base >= 0 ? RegisterByNumber(ep->ContextRecord, operand.base) : nullptr;
            DWORD64* index =
                operand.index >= 0 ? RegisterByNumber(ep->ContextRecord, operand.index) : nullptr;
            uintptr_t effective = 0;
            if (base) {
                effective += (uintptr_t)*base;
            }
            if (index) {
                effective += (uintptr_t)*index * (uintptr_t)operand.scale;
            }
            effective += (uintptr_t)operand.displacement;
            if (effective == target) {
                // Both candidates may hold a stale offset. The stale one is the
                // larger value: the arena offsets the protector uses are far
                // bigger than the small constants that take part in the address.
                // The index can only carry the offset when the scale is one, or
                // the address would move by the wrong multiple.
                const uintptr_t baseValue = base ? (uintptr_t)*base : 0;
                const uintptr_t indexValue = index ? (uintptr_t)*index : 0;
                const bool baseIsStale = base && baseValue > 0 && baseValue < kArenaSize;
                const bool indexIsStale =
                    index && operand.scale == 1 && indexValue > 0 && indexValue < kArenaSize;
                DWORD64* chosen = nullptr;
                if (baseIsStale && indexIsStale) {
                    chosen = baseValue >= indexValue ? base : index;
                } else if (baseIsStale) {
                    chosen = base;
                } else if (indexIsStale) {
                    chosen = index;
                }
                if (chosen) {
                    const uintptr_t stale = (uintptr_t)*chosen;
                    *chosen = static_cast<DWORD64>(arena + stale);
                    ++relocated;
                    relocatedFrom = stale;
                }
            }
        }
    }
    if (!relocated) {
        // The faulting address is "stale base + index", so the register holding
        // the stale base is the one to repair. It is the largest small value
        // among the registers: the arena offsets the protector uses are far
        // larger than the indices it adds to them.
        uintptr_t best = 0;
        for (DWORD64* reg : registers) {
            const uintptr_t value = (uintptr_t)*reg;
            if (value > 0 && value < kArenaSize && value <= target && value > best) {
                best = value;
            }
        }
        if (best) {
            for (DWORD64* reg : registers) {
                if ((uintptr_t)*reg == best) {
                    *reg = static_cast<DWORD64>(arena + best);
                    ++relocated;
                    relocatedFrom = best;
                    break;
                }
            }
        }
    }
    if (!relocated) {
        RecordFault("arena-nomatch", ep);
        _InterlockedExchange(&g_publishBusy, 0);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    RecordFault(fault == bootVa ? "arena-bootstrap" : "arena-relocate", ep);
    // The protector cached this offset in its own data before the arena was
    // published. Repairing the register fixes this access; rewriting the cached
    // copies stops the protector from faulting on the same value thousands of
    // times.
    if (relocatedFrom) {
        QueueCachedOffset(relocatedFrom);
        char queued[64]{};
        size_t used = 0;
        const char* label = "queued=";
        while (*label && used + 1 < sizeof(queued)) {
            queued[used++] = *label++;
        }
        used += FormatHex(queued + used, sizeof(queued) - used, relocatedFrom);
        if (used + 2 < sizeof(queued)) {
            queued[used++] = '\r';
            queued[used++] = '\n';
        }
        AppendRaw(queued, used);
    }
    _InterlockedExchange(&g_publishBusy, 0);
    return EXCEPTION_CONTINUE_EXECUTION;
}

// =================================================================================================
// FAULT RECORDER
//
// A vectored exception handler must not do file I/O, allocate, or format strings: a fault
// inside any of those turns the diagnostic into the crash. Everything the handler learns is
// therefore copied into a fixed ring buffer, and an ordinary worker thread drains that
// buffer to the log file.
// =================================================================================================

struct FaultRecord {
    volatile LONG sequence; // published last; readers wait for it to change
    uintptr_t rip;
    uintptr_t target;
    uint64_t access;
    uint64_t registers[16];
    unsigned char code[24];
    char tag[24];
};

static constexpr LONG kFaultRingSize = 256;
static FaultRecord g_faults[kFaultRingSize];
static volatile LONG g_faultWrite = 0;
static volatile LONG g_faultRead = 0;

// Copy the fault context into the ring. Safe to call from a vectored handler:
// fixed memory, no allocation, no system calls beyond a memory read.
static void RecordFault(const char* tag, EXCEPTION_POINTERS* ep) {
    if (!ShouldReportFault((uintptr_t)ep->ContextRecord->Rip)) {
        return;
    }
    const long index = (long)(_InterlockedIncrement(&g_faultWrite) - 1);
    FaultRecord& record = g_faults[((index % kFaultRingSize) + kFaultRingSize) % kFaultRingSize];
    record.rip = (uintptr_t)ep->ContextRecord->Rip;
    record.target = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
    record.access = (uint64_t)ep->ExceptionRecord->ExceptionInformation[0];
    record.registers[0] = (uint64_t)ep->ContextRecord->Rax;
    record.registers[1] = (uint64_t)ep->ContextRecord->Rbx;
    record.registers[2] = (uint64_t)ep->ContextRecord->Rcx;
    record.registers[3] = (uint64_t)ep->ContextRecord->Rdx;
    record.registers[4] = (uint64_t)ep->ContextRecord->Rsi;
    record.registers[5] = (uint64_t)ep->ContextRecord->Rdi;
    record.registers[6] = (uint64_t)ep->ContextRecord->R8;
    record.registers[7] = (uint64_t)ep->ContextRecord->R9;
    record.registers[8] = (uint64_t)ep->ContextRecord->R10;
    record.registers[9] = (uint64_t)ep->ContextRecord->R11;
    record.registers[10] = (uint64_t)ep->ContextRecord->R12;
    record.registers[11] = (uint64_t)ep->ContextRecord->R13;
    record.registers[12] = (uint64_t)ep->ContextRecord->R14;
    record.registers[13] = (uint64_t)ep->ContextRecord->R15;
    record.registers[14] = (uint64_t)ep->ContextRecord->Rsp;
    record.registers[15] = (uint64_t)ep->ContextRecord->Rbp;
    SIZE_T read = 0;
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)record.rip, record.code, sizeof(record.code), &read);
    if (read < sizeof(record.code)) {
        memset(record.code + read, 0, sizeof(record.code) - read);
    }
    strncpy_s(record.tag, sizeof(record.tag), tag, _TRUNCATE);
    InterlockedExchange(&record.sequence, (LONG)(index + 1));
    // Also write a compact line immediately: a fatal fault can end the process
    // before the ring is drained.
    char line[512];
    size_t used = 0;
    const char* prefix = tag;
    while (*prefix && used + 1 < sizeof(line)) {
        line[used++] = *prefix++;
    }
    static const char* kNames[] = {
        " rip=", " target=", " access=", " rax=", " rbx=", " rcx=", " rdx=", " rsi=", " rdi=",
        " r8=",  " r9=",     " r10=",    " r11=", " r12=", " r13=", " r14=", " r15="};
    const unsigned long long values[] = {
        (unsigned long long)ep->ContextRecord->Rip,
        (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1],
        (unsigned long long)ep->ExceptionRecord->ExceptionInformation[0],
        (unsigned long long)ep->ContextRecord->Rax,
        (unsigned long long)ep->ContextRecord->Rbx,
        (unsigned long long)ep->ContextRecord->Rcx,
        (unsigned long long)ep->ContextRecord->Rdx,
        (unsigned long long)ep->ContextRecord->Rsi,
        (unsigned long long)ep->ContextRecord->Rdi,
        (unsigned long long)ep->ContextRecord->R8,
        (unsigned long long)ep->ContextRecord->R9,
        (unsigned long long)ep->ContextRecord->R10,
        (unsigned long long)ep->ContextRecord->R11,
        (unsigned long long)ep->ContextRecord->R12,
        (unsigned long long)ep->ContextRecord->R13,
        (unsigned long long)ep->ContextRecord->R14,
        (unsigned long long)ep->ContextRecord->R15,
    };
    for (int f = 0; f < 17; ++f) {
        const char* text = kNames[f];
        while (*text && used + 1 < sizeof(line)) {
            line[used++] = *text++;
        }
        used += FormatHex(line + used, sizeof(line) - used, values[f]);
    }
    if (used + 2 < sizeof(line)) {
        line[used++] = '\r';
        line[used++] = '\n';
    }
    AppendRaw(line, used);
}

// Drain the ring into the log file. Runs on an ordinary thread, so it may use the CRT.
static DWORD WINAPI FaultLogThread(LPVOID) {
    LONG lastSeen = 0;
    ULONGLONG lastReinstall = 0;
    for (;;) {
        // The protector removes vectored exception handlers it finds while it
        // unpacks, so reinstall them periodically. Without this the faults that
        // matter are invisible and the only evidence is the WER bucket.
        const ULONGLONG now = GetTickCount64();
        if (now - lastReinstall > 2000) {
            lastReinstall = now;
            AddVectoredExceptionHandler(1, CrashWatch);
            AddVectoredExceptionHandler(1, ArenaFaultHandler);
        }
        bool wrote = false;
        for (;;) {
            const LONG writeIndex = g_faultWrite;
            if (writeIndex == lastSeen) {
                break;
            }
            const long index = (long)(writeIndex - 1);
            FaultRecord& record = g_faults[((index % kFaultRingSize) + kFaultRingSize) % kFaultRingSize];
            const LONG sequence = record.sequence;
            if (sequence != index + 1) {
                break; // still being written
            }
            // Copy the record out, then confirm it was not overwritten while it
            // was being copied. The fault rate here is high enough that the
            // writer can lap the reader, and a torn record mixes one fault's
            // registers with another fault's instruction bytes.
            FaultRecord copy = record;
            if (record.sequence != sequence) {
                continue;
            }
            lastSeen = index + 1;

            char code[80]{};
            size_t used = 0;
            used += (size_t)snprintf(code + used, sizeof(code) - used, " code:");
            for (size_t i = 0; i < sizeof(copy.code) && used < sizeof(code) - 4; ++i) {
                used += (size_t)snprintf(code + used, sizeof(code) - used, " %02X", copy.code[i]);
            }
            Log("%s: rip=0x%llX target=0x%llX access=%llu%s", copy.tag, (unsigned long long)copy.rip,
                (unsigned long long)copy.target, (unsigned long long)copy.access, code);
            Log("%s: rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rsi=0x%llX rdi=0x%llX", copy.tag,
                (unsigned long long)copy.registers[0], (unsigned long long)copy.registers[1],
                (unsigned long long)copy.registers[2], (unsigned long long)copy.registers[3],
                (unsigned long long)copy.registers[4], (unsigned long long)copy.registers[5]);
            Log("%s: r8=0x%llX r9=0x%llX r10=0x%llX r11=0x%llX r12=0x%llX r13=0x%llX", copy.tag,
                (unsigned long long)copy.registers[6], (unsigned long long)copy.registers[7],
                (unsigned long long)copy.registers[8], (unsigned long long)copy.registers[9],
                (unsigned long long)copy.registers[10], (unsigned long long)copy.registers[11]);
            wrote = true;
        }
        if (!wrote) {
            Sleep(5);
        }
    }
    return 0;
}

static LONG CALLBACK CrashWatch(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // The bootstrap fault is handled (and logged) by ArenaFaultHandler.
    uintptr_t fault = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
    if (g_protectorBase && fault == g_protectorBase + kBootstrapOffset) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    RecordFault("crash", ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

// Find the real protector's module. The proxy itself is also called
// "Referee.dll", so the module list has to be walked and matched by path.
static uintptr_t FindProtectorModule() {
    if (g_protectorBase) {
        return g_protectorBase;
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    MODULEENTRY32W mod{};
    mod.dwSize = sizeof(mod);
    uintptr_t found = 0;
    if (Module32FirstW(snap, &mod)) {
        do {
            if (_wcsicmp(mod.szModule, L"Referee.dll") != 0) {
                continue;
            }
            if (wcsstr(mod.szExePath, L"preserve\\") == nullptr) {
                continue;
            }
            found = (uintptr_t)mod.modBaseAddr;
            break;
        } while (Module32NextW(snap, &mod));
    }
    CloseHandle(snap);
    return found;
}

// =================================================================================================
// ARENA SLOT WATCHPOINT
//
// The protector keeps its arena pointer in a local variable and stores the ADDRESS of
// that local in the slot at Referee+ArenaSlot. The out-of-process publisher therefore writes
// the arena straight into the protector's own stack frame, and it does so between the
// store and the protector's first read of that frame.
//
// In-process we cannot run concurrently with the protector's DllMain: the loader lock
// keeps a second thread from starting, so a polling thread never gets a turn before
// the protector has already read a null arena and cached thousands of offsets derived
// from it.
//
// A hardware write watchpoint on the slot closes that window without any timing race.
// The protector's DllMain runs on THIS thread (the one that calls LoadLibrary), so
// arming a watchpoint here means the exception is raised the instant the protector
// stores its local's address -- after the store, so the slot already holds the address,
// and before the protector's next instruction reads it. The arena can then be written
// into that frame and the protector's first read is correct. No offsets are ever
// derived from a null base, and the whole repair storm disappears.
// =================================================================================================

static uintptr_t g_watchedSlot = 0;

// Arm a write watchpoint on the slot. The CPU requires every other thread in the
// process to have its debug registers disabled before one thread can use them.
static void ArmArenaWatchpoint(uintptr_t slot) {
    g_watchedSlot = slot;

    const DWORD currentThread = GetCurrentThreadId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32ThreadID == currentThread) {
                    continue;
                }
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                           FALSE, entry.th32ThreadID);
                if (!thread) {
                    continue;
                }
                CONTEXT context{};
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(thread, &context)) {
                    if (context.Dr7) {
                        context.Dr7 = 0;
                        SetThreadContext(thread, &context);
                    }
                }
                CloseHandle(thread);
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        Log("watchpoint: GetThreadContext failed (error %lu)", GetLastError());
        return;
    }
    context.Dr0 = slot;
    // L0 enabled, eight-byte length, write only.
    context.Dr7 = (1UL << 16) | (2UL << 18) | 1UL;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        Log("watchpoint: SetThreadContext failed (error %lu)", GetLastError());
        return;
    }
    Log("watchpoint armed on slot 0x%llX", (unsigned long long)slot);
}

static void DisarmArenaWatchpoint() {
    if (!g_watchedSlot) {
        return;
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &context)) {
        context.Dr0 = 0;
        context.Dr7 = 0;
        SetThreadContext(GetCurrentThread(), &context);
    }
    g_watchedSlot = 0;
}

// Handle the watchpoint hit: the protector has just stored the address of its arena
// local, so the slot now holds that address. Write the arena into it.
static LONG HandleArenaWatchpoint(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // For a debug register exception the data address is reported in DR6, not in
    // the exception record: DR6 bit 0 means "breakpoint 0 fired".
    const DWORD64 dr6 = ep->ContextRecord->Dr6;
    const bool breakpoint0 = (dr6 & 1) != 0;
    if (!g_watchedSlot ||
        (!breakpoint0 && (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1] != g_watchedSlot)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    uintptr_t pointer = *(uintptr_t*)g_watchedSlot;
    uintptr_t arena = g_arena;
    if (!arena) {
        arena = BuildArena();
        if (!arena) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        g_arena = arena;
    }
    if (pointer) {
        *(uintptr_t*)pointer = arena;
        Log("watchpoint: arena %p published into the protector's frame at %p", (void*)arena, (void*)pointer);
    } else {
        Log("watchpoint: slot holds a null address");
    }
    DisarmArenaWatchpoint();
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Resolve the protector's jjiEVn gate on first use; the export table only
// becomes usable once the protector's unpack finishes.
//
// The trampoline retries until this returns true, so the only way out of the
// wait is the gate appearing. A bounded retry would leave the trampoline
// jumping to a null address, which is a worse failure than a wait.
extern "C" bool EnsureGate(void) {
    if (g_realXNfn) {
        return true;
    }
    uintptr_t base = FindProtectorModule();
    if (!base) {
        static int reported = 0;
        if (reported++ < 5) {
            Log("jjiEVn gate: protector module not in the module list yet");
        }
        Sleep(50);
        return false;
    }
    g_protectorBase = base;
    // The protector finishes unpacking inside its own DllMain, so the export
    // may not be published the instant LoadLibrary returns.
    for (int i = 0; i < 200; ++i) {
        FARPROC gate = GetProcAddress((HMODULE)base, "jjiEVn");
        if (gate) {
            g_realXNfn = (unsigned long long)gate;
            Log("jjiEVn gate resolved at 0x%llX", g_realXNfn);
            return true;
        }
        Sleep(50);
    }
    Log("jjiEVn gate not published yet; still waiting");
    return false;
}

extern "C" __declspec(dllexport) void* GetPreserveProtector(void) {
    g_protectorBase = FindProtectorModule();
    return (void*)g_protectorBase;
}

static DWORD WINAPI BootstrapThread(LPVOID) {
    // Wait for the protector to have unpacked the client and GameAssembly.dll
    // to appear as a loaded module. ~2 minutes of polling at 50ms is far past
    // any realistic load time on this build.
    for (int i = 0; i < 2400; ++i) {
        if (GetModuleHandleW(L"GameAssembly.dll")) {
            Sleep(300);

            wchar_t dir[MAX_PATH] = {};
            GetModuleDir(nullptr, dir, MAX_PATH);
            std::wstring modulesDir = std::wstring(dir) + L"\\preserve\\modules";
            std::wstring pattern = modulesDir + L"\\*.dll";

            WIN32_FIND_DATAW fd = {};
            HANDLE search = FindFirstFileW(pattern.c_str(), &fd);
            std::vector<std::wstring> modules;
            if (search != INVALID_HANDLE_VALUE) {
                do {
                    modules.emplace_back(fd.cFileName);
                } while (FindNextFileW(search, &fd));
                FindClose(search);
            }
            std::sort(modules.begin(), modules.end(), [](const std::wstring& a, const std::wstring& b) {
                return _wcsicmp(a.c_str(), b.c_str()) < 0;
            });

            if (modules.empty()) {
                Log("no modules found in %ls; client is running unpatched", modulesDir.c_str());
                return 0;
            }

            for (const auto& name : modules) {
                std::wstring full = modulesDir + L"\\" + name;
                HMODULE module = LoadLibraryW(full.c_str());
                if (module) {
                    Log("loaded %ls (module=%p)", name.c_str(), (void*)module);
                } else {
                    Log("FAILED to load %ls (error %lu); continuing", name.c_str(), GetLastError());
                }
            }
            return 0;
        }
        Sleep(50);
    }
    Log("timed out waiting for GameAssembly.dll; modules not attached");
    return 1;
}

static void GetModuleDir(HMODULE module, wchar_t* out, size_t outCount) {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(module, path, MAX_PATH);
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash) {
        *slash = L'\0';
    }
    wcsncpy_s(out, outCount, path, _TRUNCATE);
}

// Log without the C runtime.
//
// The arena publisher runs as a thread created inside DllMain, so it starts while the
// loader lock is held. A CRT call there can block on the CRT's own init lock, which
// would stall the publisher until the protector's DllMain finished -- exactly the race
// this thread exists to win. Win32 file APIs have no such dependency, so the log
// uses them directly.
static void Log(const char* fmt, ...) {
    // Re-entrancy guard: a fault inside this function would re-enter it
    // through the vectored handler and recurse until the stack ran out. It is
    // per thread so that the fault reporter and the repair worker can log at
    // the same time instead of dropping each other's lines.
    static __declspec(thread) LONG busy = 0;
    if (_InterlockedCompareExchange(&busy, 1, 0) != 0) {
        return;
    }

    char line[1024]{};
    va_list args;
    va_start(args, fmt);
    const int formatted = _vsnprintf_s(line, sizeof(line), _TRUNCATE, fmt, args);
    va_end(args);
    if (formatted < 0) {
        _InterlockedExchange(&busy, 0);
        return;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    char stamp[32]{};
    _snprintf_s(stamp, _countof(stamp), _TRUNCATE, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

    // No heap and no CRT allocation here: this runs inside a vectored exception
    // handler, where an allocation can fault or deadlock on the CRT lock and
    // take the whole process with it.
    char body[1200]{};
    const int written = _snprintf_s(body, sizeof(body), _TRUNCATE, "%s%s\r\n", stamp, line);
    if (written > 0) {
        AppendRaw(body, static_cast<size_t>(written));
    }
    _InterlockedExchange(&busy, 0);
}

// Open the log file once. Keeping the handle open means a fault handler never
// has to resolve a path or open a file.
static void OpenLogFile() {
    if (g_logHandle != INVALID_HANDLE_VALUE) {
        return;
    }
    wchar_t dir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) {
        *slash = L'\0';
    }
    wchar_t logPath[MAX_PATH + 80]{};
    _snwprintf_s(logPath, _countof(logPath), _TRUNCATE, L"%s\\preserve-loader.log", dir);
    g_logHandle = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        OpenLogFile();
        Log("proxy attached; loading the protector");

        wchar_t dir[MAX_PATH] = {};
        GetModuleDir(nullptr, dir, MAX_PATH);
        std::wstring subPath = std::wstring(dir) + L"\\preserve\\Referee.dll";

        // Read the protector's preferred base before loading it: the arena
        // fault fires inside the protector's DllMain, before LoadLibrary
        // returns and before the module list can be queried.
        g_expectedBase = ReadImageBaseFromFile(subPath.c_str());
        Log("protector preferred base = 0x%llX", (unsigned long long)g_expectedBase);

        // The protector's DllMain faults on the retired service's arena before
        // LoadLibrary returns, so the handler must already be installed. Keep it
        // for the process lifetime.
        AddVectoredExceptionHandler(1, CrashWatch);
        PVOID veh = AddVectoredExceptionHandler(1, ArenaFaultHandler);
        Log("vectored handlers installed (arena=%p)", veh);

        // Build the arena up front and watch the slot the protector uses to
        // publish the address of its own arena variable. The watchpoint closes
        // the window between that store and the protector's first read, which
        // is the same window the out-of-process publisher used. Without it the
        // protector derives its arena offsets from a null base and the client
        // never reaches a consistent state.
        {
            const uintptr_t arena = BuildArena();
            if (arena) {
                g_arena = arena;
                ArmArenaWatchpoint(g_expectedBase + kArenaSlotOffset);
            }
        }

        g_protectorBase = (uintptr_t)LoadLibraryW(subPath.c_str());
        if (!g_protectorBase) {
            Log("FATAL: protector not found or failed to load (error %lu)", GetLastError());
            return FALSE; // fail closed; the client cannot run without its protector
        }
        Log("protector loaded at 0x%llX", (unsigned long long)g_protectorBase);

        // The protector's unpack can tear down vectored exception handlers it
        // finds, so reinstall both after the load. Without this the post-load
        // faults are invisible and the only evidence is the WER bucket.
        AddVectoredExceptionHandler(1, CrashWatch);
        AddVectoredExceptionHandler(1, ArenaFaultHandler);
        Log("vectored handlers reinstalled after the protector's unpack");

        // Drain the fault ring to the log file from an ordinary thread. The
        // vectored handler itself only copies into memory.
        HANDLE faultLog = CreateThread(nullptr, 0, FaultLogThread, nullptr, 0, nullptr);
        if (faultLog) {
            CloseHandle(faultLog);
        } else {
            Log("CreateThread failed (error %lu); fault log disabled", GetLastError());
        }

        // Rewrite the stale arena offsets the protector cached before the arena
        // was published. Without this the protector re-reads the same bad
        // pointers thousands of times a second.
        HANDLE patcher = CreateThread(nullptr, 0, CachedOffsetPatchThread, nullptr, 0, nullptr);
        if (patcher) {
            CloseHandle(patcher);
        } else {
            Log("CreateThread failed (error %lu); cached offsets not repaired", GetLastError());
        }

        // The slot may only become valid later; make sure the arena is
        // published even if the bootstrap fault was handled elsewhere.
        PublishArenaAt(g_protectorBase);

        HANDLE watcher = CreateThread(nullptr, 0, BootstrapThread, nullptr, 0, nullptr);
        if (watcher) {
            CloseHandle(watcher);
        } else {
            Log("CreateThread failed (error %lu); modules not attached", GetLastError());
        }
    }
    return TRUE;
}
