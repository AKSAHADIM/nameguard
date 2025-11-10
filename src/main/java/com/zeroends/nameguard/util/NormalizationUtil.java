package com.zeroends.nameguard.util;

import org.jetbrains.annotations.NotNull;

import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Utility class for normalizing player names to prevent spoofing via casing or similar characters.
 *
 * V4 Patch:
 * - Menambahkan penghapusan prefix Floodgate/Geyser (misal "." di depan nama Bedrock).
 * - Tujuannya: ".Finkiramman" dan "Finkiramman" dianggap identitas yang sama sehingga
 *   tidak terjadi penolakan CONFUSABLE_NAME_SPOOF hanya karena reconnect memakai prefix.
 *
 * Catatan:
 * - Jika Anda menambahkan prefix lain di konfigurasi Floodgate (misal "!" atau "~"),
 *   Anda bisa memperluas pola REGEX_PREFIX_STRIP.
 */
public class NormalizationUtil {

    // Pattern untuk menghapus diakritik (aksen) setelah normalisasi NFKD
    private static final Pattern DIACRITICS = Pattern.compile("\\p{InCombiningDiacriticalMarks}+");

    // Pattern prefix legacy Floodgate/Geyser di awal nama (satu atau lebih titik).
    // Bisa diperluas: "^([\\.!~]+)" untuk mendukung beberapa karakter.
    private static final Pattern REGEX_PREFIX_STRIP = Pattern.compile("^\\.+");

    /**
     * Normalizes a player name to a canonical form.
     *
     * Langkah:
     * 1. Strip prefix legacy (misal "." di depan nama Bedrock) agar variasi reconnect konsisten.
     * 2. Unicode normalize (NFKD) untuk memecah karakter dengan aksen.
     * 3. Hapus diakritik.
     * 4. Konversi ke lowercase.
     * 5. Hapus semua karakter non [a-z0-9_] untuk menyempitkan ruang spoof.
     *
     * @param input Raw player name.
     * @return Normalized canonical string (tanpa prefix & bebas aksen).
     */
    @NotNull
    public String normalizeName(@NotNull String input) {
        // 1. Strip prefix "." (atau pattern yang diset) di depan nama
        String withoutPrefix = REGEX_PREFIX_STRIP.matcher(input).replaceFirst("");

        // 2. Normalize NFKD
        String normalized = Normalizer.normalize(withoutPrefix, Normalizer.Form.NFKD);

        // 3. Remove diacritics
        String stripped = DIACRITICS.matcher(normalized).replaceAll("");

        // 4 & 5. Lowercase + keep only [a-z0-9_]
        return stripped.toLowerCase()
                .replaceAll("[^a-z0-9_]", "");
    }
}
