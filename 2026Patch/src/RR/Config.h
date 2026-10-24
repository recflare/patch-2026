#pragma once

#include <windows.h>
#include <fstream>
#include "NetworkConfig.h"

namespace RR::Config {
    // One snapshot feeds both preflight and the DLL. Runtime callbacks copy the
    // values they need; there is no live INI reload while hooks are executing.
    // Zero FPS and false flags are native-behavior defaults when options are absent.
    // SuppressDuidMismatch keeps the 2025 patch's default of true: it changes
    // nothing on machines whose stored device ID already matches.
    struct Settings {
        Network network;
        std::string voiceKeyXml;
        int framesPerSecond = 0;
        bool verbose = false;
        bool suppressDuidMismatch = true;
    };

    // Win32 INI reads return the fallback for an absent field. Empty routing
    // values are intentional, not a parse error. Reject truncation before UTF-8
    // conversion so a shortened hostname or RSA key cannot become an override.
    inline bool ReadIni(const std::wstring& path, const wchar_t* name, std::string& value) {
        wchar_t text[4098]{};
        char utf8[16392]{};
        const DWORD length = GetPrivateProfileStringW(L"config", name, L"", text, 4098, path.c_str());
        if (length >= 4097 || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, utf8,
                                                   sizeof(utf8), nullptr, nullptr)) {
            return false;
        }
        value = utf8;
        return true;
    }

    // Flags use the 2025 patch's spellings (true/false, 1/0, yes/no, on/off).
    // An absent or blank flag keeps the caller's native-behavior default; any
    // other text is rejected instead of being read as a silent false.
    inline bool ReadFlag(const std::wstring& path, const wchar_t* name, bool& value) {
        std::string text;
        if (!ReadIni(path, name, text)) {
            return false;
        }
        text = Lower(text);
        if (text == "true" || text == "1" || text == "yes" || text == "on") {
            value = true;
        } else if (text == "false" || text == "0" || text == "no" || text == "off") {
            value = false;
        } else if (!text.empty()) {
            return false;
        }
        return true;
    }

    // The file itself must exist, but ApiHost and ServerDomain can be omitted
    // independently. Validate supplied values before installing any hooks; avoid
    // silently mixing a mistyped operator endpoint with the client's fallback.
    inline bool Load(const std::wstring& path, Settings& settings, std::string& error) {
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            error = "2026patch.ini is missing. Place it beside 2026patch.dll.";
            return false;
        }
        // Settings moved to the 2025 patch's single [config] section. A file in
        // the earlier layout would parse and apply nothing, which is
        // indistinguishable from an unconfigured install, so refuse it.
        for (const wchar_t* section : {L"Network", L"ScreenShare", L"Logging"}) {
            wchar_t legacy[8]{};
            if (GetPrivateProfileSectionW(section, legacy, 8, path.c_str())) {
                error = "2026patch.ini uses the previous section layout. Move every setting under [config]; "
                        "ServerUrl is now ApiHost and Verbose is now EnableTracing.";
                return false;
            }
        }
        if (!ReadIni(path, L"ApiHost", settings.network.apiHost) ||
            !ReadIni(path, L"ServerDomain", settings.network.serverDomain) ||
            !ReadIni(path, L"CachedServerDomain", settings.network.cachedServerDomain) ||
            !ReadIni(path, L"VoiceKeyXml", settings.voiceKeyXml)) {
            error = "A configuration setting is too long or contains invalid text.";
            return false;
        }
        settings.network.serverDomain = Lower(settings.network.serverDomain);
        settings.network.cachedServerDomain = Lower(settings.network.cachedServerDomain);
        if (!settings.network.Valid()) {
            error = "When supplied, ApiHost must be a host name or HTTP(S) origin and ServerDomain a valid "
                    "service domain covering it.";
            return false;
        }
        if (!ReadFlag(path, L"DisableCertificatePinning", settings.network.disableCertificatePinning) ||
            !ReadFlag(path, L"AllowUnsignedImages", settings.network.allowUnsignedImages) ||
            !ReadFlag(path, L"EnableTracing", settings.verbose) ||
            !ReadFlag(path, L"SuppressDuidMismatch", settings.suppressDuidMismatch)) {
            error = "DisableCertificatePinning, AllowUnsignedImages, EnableTracing and SuppressDuidMismatch "
                    "must be "
                    "true or false.";
            return false;
        }
        settings.framesPerSecond =
            static_cast<int>(GetPrivateProfileIntW(L"config", L"FramesPerSecond", 0, path.c_str()));
        if (settings.framesPerSecond < 0 || settings.framesPerSecond > 60) {
            error = "FramesPerSecond must be between 0 and 60 (0 retains the client presets).";
            return false;
        }
        // The developer launcher override is process-local and applied after the
        // INI. Both injector and client inherit it, so preflight sees exactly
        // the same key as the DLL. A public-key file path is never logged.
        wchar_t keyPath[32768]{};
        const DWORD keyLength = GetEnvironmentVariableW(L"PATCH26_TACHYON_PUBLIC_KEY", keyPath, 32768);
        if (keyLength >= 32768) {
            error = "Public key path is too long.";
            return false;
        }
        if (keyLength) {
            std::ifstream input(keyPath, std::ios::binary);
            char key[4097]{};
            if (!input) {
                error = "Cannot open the Tachyon public key file.";
                return false;
            }
            input.read(key, sizeof(key));
            settings.voiceKeyXml.assign(key, static_cast<size_t>(input.gcount()));
            if (settings.voiceKeyXml.empty()) {
                error = "The public key file is empty.";
                return false;
            }
        }
        // Private RSA material belongs on the server and is rejected here; the
        // endpoint and server ID always come from matchmaking.
        if (!settings.voiceKeyXml.empty() && !PublicKey(settings.voiceKeyXml)) {
            error = "VoiceKeyXml must contain only public RSA Modulus and Exponent fields.";
            return false;
        }
        return true;
    }
}
