package com.zeroends.nameguard.util;

import org.jetbrains.annotations.NotNull;

import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Utility class for normalizing player names to prevent spoofing via casing or similar characters.
 *
 * Important:
 * - Preserves Floodgate/Geyser prefix (e.g., "." at the beginning of Bedrock player names).
 * - This ensures that Bedrock players connecting via Geyser/Floodgate are correctly identified
 *   and tracked without session conflicts.
 * - The dot prefix is essential for distinguishing Bedrock players from Java Edition players.
 */
public class NormalizationUtil {

    // Pattern untuk menghapus diakritik (aksen) setelah normalisasi NFKD
    private static final Pattern DIACRITICS = Pattern.compile("\\p{InCombiningDiacriticalMarks}+");

    /**
     * Normalizes a player name to a canonical form.
     *
     * Steps:
     * 1. Unicode normalize (NFKD) to decompose characters with accents.
     * 2. Remove diacritics (combining marks).
     * 3. Convert to lowercase.
     * 4. Keep only alphanumeric characters, underscores, and dots (for Bedrock prefix).
     *
     * Note: The dot prefix (.) is preserved for Bedrock Edition players using Geyser/Floodgate.
     * This ensures proper player identification and prevents session conflicts.
     *
     * @param input Raw player name.
     * @return Normalized canonical string (with preserved dot prefix if present).
     */
    @NotNull
    public String normalizeName(@NotNull String input) {
        // 1. Normalize NFKD
        String normalized = Normalizer.normalize(input, Normalizer.Form.NFKD);

        // 2. Remove diacritics
        String stripped = DIACRITICS.matcher(normalized).replaceAll("");

        // 3 & 4. Lowercase + keep only [a-z0-9_.] (preserving dot for Bedrock players)
        return stripped.toLowerCase()
                .replaceAll("[^a-z0-9_.]", "");
    }
}
