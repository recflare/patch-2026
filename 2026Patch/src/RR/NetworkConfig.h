#pragma once

#include <algorithm>
#include <cctype>
#include <string>

namespace RR::Config {
    inline std::string Lower(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    }

    // Restricted ASCII hostname grammar shared by URL and transport validation.
    // This deliberately excludes credentials, bracketed IPv6 and trailing-dot
    // aliases; Tachyon's verified parser ultimately consumes numeric IPv4.
    inline bool Host(const std::string& host) {
        if (host.empty() || host.size() > 253 || host.back() == '.') {
            return false;
        }
        size_t start = 0;
        while (start < host.size()) {
            const size_t end = host.find('.', start);
            const size_t length = (end == std::string::npos ? host.size() : end) - start;
            if (!length || length > 63 || host[start] == '-' || host[start + length - 1] == '-') {
                return false;
            }
            for (size_t i = start; i < start + length; ++i) {
                const unsigned char c = host[i];
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
                    return false;
                }
            }
            if (end == std::string::npos) {
                break;
            }
            start = end + 1;
        }
        return true;
    }

    inline bool Endpoint(const std::string& value, std::string& host, std::string& port) {
        const auto split = value.rfind(':');
        if (split == std::string::npos) {
            return false;
        }
        host = Lower(value.substr(0, split));
        port = value.substr(split + 1);
        if (!Host(host) || port.empty() || port.size() > 5 ||
            port.find_first_not_of("0123456789") != std::string::npos) {
            return false;
        }
        const int number = std::stoi(port);
        return number >= 1 && number <= 65535;
    }

    struct Url {
        std::string scheme, host, port;
        size_t authorityStart = 0, authorityEnd = 0;
    };

    // Parse only enough to establish scheme and authority boundaries. Preserve
    // path/query/fragment bytes when rewriting; they may contain signed data.
    // This is not a general browser URL parser: unsupported authorities fail
    // validation instead of being normalized into a different service host.
    inline bool ParseUrl(const std::string& value, Url& url) {
        const auto split = value.find("://");
        if (split == std::string::npos) {
            return false;
        }
        url.scheme = Lower(value.substr(0, split));
        if (url.scheme != "https" && url.scheme != "http" && url.scheme != "wss" && url.scheme != "ws") {
            return false;
        }
        url.authorityStart = split + 3;
        url.authorityEnd = value.find_first_of("/?#", url.authorityStart);
        if (url.authorityEnd == std::string::npos) {
            url.authorityEnd = value.size();
        }
        const auto authority = value.substr(url.authorityStart, url.authorityEnd - url.authorityStart);
        url.port.clear();
        if (authority.find(':') != std::string::npos) {
            return Endpoint(authority, url.host, url.port);
        }
        url.host = Lower(authority);
        return Host(url.host);
    }

    // A suffix match alone would include lookalikes such as notexample.com.
    // Require equality or the separating dot; an empty domain grants no scope.
    inline bool InDomain(const std::string& host, const std::string& domain) {
        return !domain.empty() &&
               (host == domain || (host.size() > domain.size() &&
                                   host.compare(host.size() - domain.size(), domain.size(), domain) == 0 &&
                                   host[host.size() - domain.size() - 1] == '.'));
    }

    struct Network {
        std::string apiHost, serverDomain, cachedServerDomain;
        bool disableCertificatePinning = false;
        bool allowUnsignedImages = false;

        // ApiHost shares the 2025 patch's key. A bare host[:port] replaces only
        // the authority, so the request keeps its scheme as it does there; a
        // full http(s) origin replaces the scheme as well.
        bool ApiOrigin() const {
            return apiHost.find("://") != std::string::npos;
        }

        bool Valid() const {
            Url url;
            const std::string origin = ApiOrigin() ? apiHost : "https://" + apiHost;
            if (!apiHost.empty() &&
                (!ParseUrl(origin, url) || (url.scheme != "https" && url.scheme != "http") ||
                 url.authorityEnd != origin.size())) {
                return false;
            }
            return (serverDomain.empty() || Host(serverDomain)) &&
                   (apiHost.empty() || serverDomain.empty() || InDomain(url.host, serverDomain)) &&
                   (cachedServerDomain.empty() || Host(cachedServerDomain));
        }

        // ns.rec.net is the stock client's discovery seam, not an operator
        // default. Replace its origin only when configured. Service discovery
        // still supplies other endpoints; cached-domain migration changes only
        // explicitly recognized old hosts, retaining service prefixes and ports.
        bool Rewrite(std::string& value) const {
            Url url;
            if (!ParseUrl(value, url)) {
                return false;
            }
            if (!apiHost.empty() && url.host == "ns.rec.net" &&
                (url.scheme == "https" || url.scheme == "http")) {
                if (ApiOrigin()) {
                    value.replace(0, url.authorityEnd, apiHost);
                } else {
                    value.replace(url.authorityStart, url.authorityEnd - url.authorityStart, apiHost);
                }
                return true;
            }
            // Current hosts take precedence when the old domain is a parent of
            // the new one; otherwise a fresh URL could be migrated a second time.
            if (InDomain(url.host, serverDomain)) {
                return false;
            }
            if (!serverDomain.empty() && !cachedServerDomain.empty() && cachedServerDomain != serverDomain &&
                InDomain(url.host, cachedServerDomain)) {
                const auto host =
                    url.host.substr(0, url.host.size() - cachedServerDomain.size()) + serverDomain;
                value.replace(url.authorityStart, url.authorityEnd - url.authorityStart,
                              host + (url.port.empty() ? "" : ":" + url.port));
                return true;
            }
            return false;
        }

        bool Owns(const std::string& value) const {
            Url url;
            return ParseUrl(value, url) && InDomain(url.host, serverDomain);
        }
    };

    // Accept only the small .NET RSA public-key shape, with each field once.
    // This avoids general XML features (entities, attributes, nested elements)
    // and explicitly excludes private-key fields. Base64 syntax is checked here;
    // the verified RSA provider performs the actual key import at runtime.
    inline bool PublicKey(const std::string& xml) {
        if (xml.size() > 4096) {
            return false;
        }
        size_t cursor = 0;
        auto skipSpace = [&]() {
            while (cursor < xml.size() && std::isspace(static_cast<unsigned char>(xml[cursor]))) {
                ++cursor;
            }
        };
        auto consume = [&](const std::string& token) {
            skipSpace();
            if (xml.compare(cursor, token.size(), token) != 0) {
                return false;
            }
            cursor += token.size();
            return true;
        };
        if (!consume("<RSAKeyValue>")) {
            return false;
        }
        bool modulus = false, exponent = false;
        for (int i = 0; i < 2; ++i) {
            skipSpace();
            std::string field;
            if (xml.compare(cursor, 9, "<Modulus>") == 0 && !modulus) {
                field = "Modulus";
                modulus = true;
            } else if (xml.compare(cursor, 10, "<Exponent>") == 0 && !exponent) {
                field = "Exponent";
                exponent = true;
            } else {
                return false;
            }
            cursor += field.size() + 2;
            const std::string close = "</" + field + ">";
            const auto end = xml.find(close, cursor);
            if (end == std::string::npos) {
                return false;
            }
            std::string content = xml.substr(cursor, end - cursor);
            content.erase(std::remove_if(content.begin(), content.end(),
                                         [](unsigned char c) { return std::isspace(c); }),
                          content.end());
            if (content.empty() || content.size() % 4 ||
                content.find_first_not_of(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") !=
                    std::string::npos) {
                return false;
            }
            const auto padding = content.find('=');
            if (padding != std::string::npos &&
                (padding < content.size() - 2 ||
                 content.find_first_not_of('=', padding) != std::string::npos)) {
                return false;
            }
            cursor = end + close.size();
        }
        if (!consume("</RSAKeyValue>")) {
            return false;
        }
        skipSpace();
        return modulus && exponent && cursor == xml.size();
    }
}
