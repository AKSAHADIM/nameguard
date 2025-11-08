package com.zeroends.nameguard.util;

import org.jetbrains.annotations.NotNull;

import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Utility class for normalizing player names to prevent spoofing via casing or similar characters.
 */
public class NormalizationUtil {

    // Pattern to remove diacritics (accents) after normalization to NFD
    private static final Pattern DIACRITICS = Pattern.compile("\\p{InCombiningDiacriticalMarks}+");

    /**
     * Normalizes a player name to a canonical form.
     * <p>
     * This process includes:
     * 1. Converting to lowercase (case-insensitive).
     * 2. Normalizing Unicode (NFKD) to decompose characters (e.g., 'é' -> 'e' + '´').
     * 3. Removing diacritics (the accent marks).
     * 4. Removing non-alphanumeric characters (except underscore, common in names).
     *
     * @param input The raw player name.
     * @return The normalized, canonical name string.
     */
    @NotNull
    public String normalizeName(@NotNull String input) {
        // 1. Normalize to NFKD form to separate base characters from accents
        String normalized = Normalizer.normalize(input, Normalizer.Form.NFKD);

        // 2. Remove the diacritics (accents)
        String stripped = DIACRITICS.matcher(normalized).replaceAll("");

        // 3. Convert to lowercase and remove characters that are not
        // standard letters, numbers, or underscores.
        // This helps filter out many "confusable" characters.
        return stripped.toLowerCase()
                .replaceAll("[^a-z0-9_]", "");
    }
}
