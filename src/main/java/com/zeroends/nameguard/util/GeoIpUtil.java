package com.zeroends.nameguard.util;

import com.zeroends.nameguard.manager.ConfigManager;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GeoIpUtil
 *
 * Lightweight resolver untuk mengambil informasi Geo-IP dari layanan publik ipwho.is
 * tanpa perlu akun. Util ini berfungsi opsional: jika geo.enabled = false di config, pemanggil
 * sebaiknya tidak melakukan lookup.
 *
 * Fitur:
 *  - Cache in-memory (TTL configurable) agar tidak memukul API setiap login.
 *  - Timeout koneksi/read pendek agar tidak memperlambat jalur login.
 *  - Graceful fallback: jika gagal, kembalikan null dan fingerprint tetap dibuat tanpa geo.
 *
 * Data yang dipakai untuk fingerprint:
 *  - countryCode  (contoh: "SG")
 *  - region       (contoh: "Southeast")
 *  - city         (contoh: "Singapore")
 *  - asn          (contoh: "14061")
 *  - org          (contoh: "Digitalocean, LLC")
 *  - isp          (contoh: "Digitalocean, LLC")
 *
 * Catatan Privasi:
 *  - IP pemain dikirimkan ke ipwho.is. Jika ini tidak diinginkan, matikan fitur geo di config.yml.
 *
 * Implementasi JSON parsing:
 *  - Menghindari dependensi eksternal: parsing manual sederhana dengan pencarian token (cukup untuk field kecil).
 *  - Jika Anda ingin akurasi penuh atau field tambahan, pertimbangkan menambah library JSON (Gson/Jackson).
 */
public class GeoIpUtil {

    private final Logger logger;
    private final ConfigManager configManager;

    private final int requestTimeoutMillis;
    private final long cacheTtlMillis;

    /**
     * Entry cache menampung hasil lookup dan waktu kadaluarsanya.
     */
    private static final class CacheEntry {
        final Map<String, String> data;
        final long expiresAt;

        CacheEntry(Map<String, String> data, long expiresAt) {
            this.data = data;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public GeoIpUtil(@NotNull Logger logger, @NotNull ConfigManager configManager) {
        this.logger = logger;
        this.configManager = configManager;
        this.requestTimeoutMillis = configManager.getGeoRequestTimeoutMillis();
        this.cacheTtlMillis = configManager.getGeoCacheTtlMinutes() * 60L * 1000L;
    }

    /**
     * Melakukan lookup Geo-IP untuk sebuah InetAddress.
     * @param address InetAddress pemain.
     * @return Map berisi field geo atau null jika gagal / fitur dimatikan.
     */
    @Nullable
    public Map<String, String> lookup(@NotNull InetAddress address) {
        if (!configManager.isGeoEnabled()) {
            return null;
        }

        String ip = address.getHostAddress();
        // Cek cache
        CacheEntry entry = cache.get(ip);
        if (entry != null && !entry.isExpired()) {
            return entry.data;
        }

        Map<String, String> resolved = resolveIpWhoIs(ip);
        if (resolved == null || resolved.isEmpty()) {
            // Simpan entry kosong agar tidak spam API (negative caching singkat)
            cache.put(ip, new CacheEntry(Collections.emptyMap(), System.currentTimeMillis() + Math.min(60_000L, cacheTtlMillis)));
            return null;
        }

        cache.put(ip, new CacheEntry(resolved, System.currentTimeMillis() + cacheTtlMillis));
        return resolved;
    }

    /**
     * Melakukan HTTP GET ke ipwho.is untuk IP tertentu dan parsing manual field penting.
     * @param ip String IP (IPv4/IPv6 textual)
     * @return Map<String,String> dengan field geo atau null jika gagal.
     */
    @Nullable
    private Map<String, String> resolveIpWhoIs(@NotNull String ip) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://ipwho.is/" + ip);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(requestTimeoutMillis);
            conn.setReadTimeout(requestTimeoutMillis);

            int code = conn.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                logger.debug("[GeoIp] Non-OK HTTP status {} for IP {}", code, ip);
                return null;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder raw = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    raw.append(line);
                }
                String json = raw.toString();
                if (!json.contains("\"success\":true")) {
                    logger.debug("[GeoIp] API responded success=false for IP {}", ip);
                    return null;
                }
                return extractFields(json);
            }
        } catch (Exception e) {
            logger.debug("[GeoIp] Failed to resolve IP {}: {}", ip, e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * Parsing manual JSON sederhana.
     * Mencari nilai setelah pola "key":"value" (value di-escape sangat minimal).
     */
    @NotNull
    private Map<String, String> extractFields(@NotNull String json) {
        Map<String, String> map = new java.util.LinkedHashMap<>();

        // Helper lambda untuk ambil nilai string dari JSON single-line (tidak robust penuh, tapi cukup aman untuk format ipwho.is)
        java.util.function.Function<String, String> getVal = (key) -> {
            // Cari "key":"  atau "key":
            String pattern = "\"" + key + "\":";
            int idx = json.indexOf(pattern);
            if (idx == -1) return null;

            int start = idx + pattern.length();
            // Melewati spasi
            while (start < json.length() && (json.charAt(start) == ' ')) start++;

            // Jika nilai diawali dengan tanda kutip -> string
            if (start < json.length() && json.charAt(start) == '\"') {
                start++;
                StringBuilder sb = new StringBuilder();
                for (int i = start; i < json.length(); i++) {
                    char c = json.charAt(i);
                    if (c == '\\') { // escape
                        if (i + 1 < json.length()) {
                            sb.append(json.charAt(i + 1));
                            i++;
                        }
                    } else if (c == '\"') {
                        return sb.toString();
                    } else {
                        sb.append(c);
                    }
                }
                return sb.toString();
            } else {
                // Nilai bukan string (angka / boolean / null) sampai koma atau tutup kurung
                StringBuilder sb = new StringBuilder();
                for (int i = start; i < json.length(); i++) {
                    char c = json.charAt(i);
                    if (c == ',' || c == '}' || c == '\n') {
                        break;
                    }
                    sb.append(c);
                }
                return sb.toString().trim();
            }
        };

        putIfNonEmpty(map, "countryCode", getVal.apply("country_code"));
        putIfNonEmpty(map, "region", getVal.apply("region"));
        putIfNonEmpty(map, "city", getVal.apply("city"));

        // Bagian connection.* berada dalam nested object "connection":{ ... }
        // Parsing sederhana: cari "connection":{"asn":..., "org":...}
        putIfNonEmpty(map, "asn", getVal.apply("asn"));
        putIfNonEmpty(map, "org", getVal.apply("org"));
        putIfNonEmpty(map, "isp", getVal.apply("isp"));

        // Tambahkan waktu resolusi
        map.put("resolvedAt", Instant.now().toString());

        return map;
    }

    private void putIfNonEmpty(@NotNull Map<String, String> map, @NotNull String key, @Nullable String value) {
        if (value != null && !value.isEmpty() && !"null".equalsIgnoreCase(value)) {
            map.put(key, value);
        }
    }

    /**
     * Membersihkan cache yang sudah expired (dipanggil berkala, opsional).
     */
    public void sweepExpired() {
        for (Map.Entry<String, CacheEntry> e : cache.entrySet()) {
            if (e.getValue().isExpired()) {
                cache.remove(e.getKey());
            }
        }
    }

    /**
     * Mengembalikan map cache readonly (untuk debug / inspeksi).
     */
    @NotNull
    public Map<String, Map<String, String>> getSnapshot() {
        Map<String, Map<String, String>> snap = new LinkedHashMap<>();
        for (Map.Entry<String, CacheEntry> e : cache.entrySet()) {
            if (!e.getValue().isExpired()) {
                snap.put(e.getKey(), Collections.unmodifiableMap(e.getValue().data));
            }
        }
        return snap;
    }

    /**
     * Mengambil data Geo untuk digunakan di Fingerprint builder.
     * @param address InetAddress pemain.
     * @param builder Fingerprint.Builder tujuan.
     */
    public void enrichFingerprint(@NotNull InetAddress address, @NotNull Fingerprint.Builder builder) {
        Map<String, String> geo = lookup(address);
        if (geo == null || geo.isEmpty()) return;

        builder.countryCode(geo.get("countryCode"));
        builder.region(geo.get("region"));
        builder.city(geo.get("city"));
        builder.asn(geo.get("asn"));
        builder.org(geo.get("org"));
        builder.isp(geo.get("isp"));
    }

    @Override
    public String toString() {
        return "GeoIpUtil{cacheSize=" + cache.size() + ", ttlMillis=" + cacheTtlMillis +
                ", timeoutMillis=" + requestTimeoutMillis + ", enabled=" + configManager.isGeoEnabled() + "}";
    }

    /**
     * Static helper to build util (dipanggil dari plugin main).
     */
    @NotNull
    public static GeoIpUtil create(@NotNull Logger logger, @NotNull ConfigManager cfg) {
        Objects.requireNonNull(logger, "logger");
        Objects.requireNonNull(cfg, "configManager");
        return new GeoIpUtil(logger, cfg);
    }
}
