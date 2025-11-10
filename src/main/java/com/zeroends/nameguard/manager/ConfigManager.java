package com.zeroends.nameguard.manager;

import com.zeroends.nameguard.NameGuard;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.configuration.file.FileConfiguration;
import org.jetbrains.annotations.NotNull;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Manages loading and accessing plugin configuration values from config.yml.
 */
public class ConfigManager {

    private final NameGuard plugin;
    private FileConfiguration config;

    private final LegacyComponentSerializer legacySerializer;

    // --- Cached Config Values ---

    // Verification
    private boolean crossEditionLock;
    private int rollingFpLimit;
    private long fingerprintPurgeMillis;

    // Scoring (V3 Heuristics)
    private int scoreHardAllow;
    private int scoreSoftAllow;
    private int weightDeviceOs;
    private int weightBrand;
    private int weightEdition;
    private int weightSubnet;
    private int weightPseudoAsn;
    private int weightPtrDomain;
    private int weightIpVersion;

    // Strict verification (new)
    private boolean strictRequireNetworkOverlap;
    private int strictMinNetworkMatchesForHardAllow;
    private boolean strictAllowZeroNetworkForTrustHigh;

    // Ownership
    private long takeoverGracePeriodMillis;
    private long lowTrustPlaytimeMillis;

    // Security
    private String hmacSalt;
    private String rawKickMessage;
    private final Map<String, String> kickReasons = new HashMap<>();
    private boolean rateLimitEnabled;
    private int rateLimitAttempts;
    private long rateLimitBlockDurationMillis;

    // Geo (new - ipwho.is backed)
    private boolean geoEnabled;
    private int geoRequestTimeoutMillis;
    private int geoCacheTtlMinutes;
    private int geoWeightCountry;
    private int geoWeightAsn;
    private int geoWeightCity; // can be used as region_weight if city unreliable
    private boolean geoDisallowHardAllowOnCountryMismatch;
    private boolean geoAllowCountryMismatchForTrustHigh;

    // Messages
    private Component protectionSuccessMessage;

    // Debug
    private boolean logFailedAttempts;

    public ConfigManager(NameGuard plugin) {
        this.plugin = plugin;
        this.legacySerializer = LegacyComponentSerializer.legacySection();
    }

    /**
     * Loads (or reloads) the configuration from disk.
     */
    public void loadConfig() {
        plugin.saveDefaultConfig();
        plugin.reloadConfig();
        this.config = plugin.getConfig();

        // --- Load Verification ---
        crossEditionLock = config.getBoolean("verification.crossEditionLock", true);
        rollingFpLimit = config.getInt("verification.rollingFpLimit", 5);
        fingerprintPurgeMillis = config.getLong("verification.fingerprintPurgeDays", 90) * 24 * 60 * 60 * 1000;

        // --- Load Scoring (V3 Heuristics) ---
        scoreHardAllow = config.getInt("verification.similarity.hard_allow", 70);
        scoreSoftAllow = config.getInt("verification.similarity.soft_allow", 40);

        weightDeviceOs = config.getInt("verification.weights.deviceos_weight", 30);
        weightBrand = config.getInt("verification.weights.brand_weight", 25);
        weightEdition = config.getInt("verification.weights.edition_weight", 15);
        weightSubnet = config.getInt("verification.weights.subnet_weight", 15);
        weightPseudoAsn = config.getInt("verification.weights.pseudo_asn_weight", 8);
        weightPtrDomain = config.getInt("verification.weights.ptr_domain_weight", 5);
        weightIpVersion = config.getInt("verification.weights.ip_version_weight", 2);

        // --- Load Strict Verification (new) ---
        // Defaults are opinionated to prevent "client-only" hard allow:
        // - requireNetworkOverlap: true
        // - minNetworkMatchesForHardAllow: 1
        // - allowZeroNetworkForTrustHigh: false
        strictRequireNetworkOverlap = config.getBoolean("verification.strict.requireNetworkOverlap", true);
        strictMinNetworkMatchesForHardAllow = config.getInt("verification.strict.minNetworkMatchesForHardAllow", 1);
        strictAllowZeroNetworkForTrustHigh = config.getBoolean("verification.strict.allowZeroNetworkForTrustHigh", false);

        // --- Load Ownership ---
        takeoverGracePeriodMillis = config.getLong("ownership.takeoverGracePeriodMinutes", 1440) * 60 * 1000;
        lowTrustPlaytimeMillis = config.getLong("ownership.lowTrustPlaytimeMinutes", 15) * 60 * 1000;

        // --- Load Security ---
        hmacSalt = config.getString("security.salt", "DEFAULT_SALT_CHANGE_ME");
        if (hmacSalt.equals("GANTI_INI_DENGAN_STRING_ACAK_YANG_SANGAT_PANJANG_DAN_RAHASIA") || hmacSalt.equals("DEFAULT_SALT_CHANGE_ME")) {
            plugin.getSLF4JLogger().warn("===================================================================");
            plugin.getSLF4JLogger().warn("!!! SECURITY WARNING !!!");
            plugin.getSLF4JLogger().warn("security.salt in config.yml is insecure. Please change it!");
            plugin.getSLF4JLogger().warn("Generating a temporary salt. This is NOT recommended for production.");
            plugin.getSLF4JLogger().warn("===================================================================");
            hmacSalt = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        }

        rawKickMessage = config.getString("security.kickMessage", "&c[NameGuard]\n&fKoneksi Anda ditolak.\n&7Alasan: {reason}");

        kickReasons.clear();
        if (config.getConfigurationSection("security.reasons") != null) {
            Objects.requireNonNull(config.getConfigurationSection("security.reasons")).getKeys(false).forEach(key -> {
                String reason = config.getString("security.reasons." + key, "Alasan tidak diketahui.");
                kickReasons.put(key, reason);
            });
        }

        rateLimitEnabled = config.getBoolean("security.rateLimit.enabled", true);
        rateLimitAttempts = config.getInt("security.rateLimit.attempts", 5);
        rateLimitBlockDurationMillis = config.getLong("security.rateLimit.blockDurationSeconds", 300) * 1000;

        // --- Load Geo (ipwho.is, optional) ---
        geoEnabled = config.getBoolean("verification.geo.enabled", true);
        geoRequestTimeoutMillis = config.getInt("verification.geo.requestTimeoutMillis", 1200);
        geoCacheTtlMinutes = config.getInt("verification.geo.cacheTtlMinutes", 720);
        geoWeightCountry = config.getInt("verification.geo.weights.country_weight", 18);
        geoWeightAsn = config.getInt("verification.geo.weights.asn_weight", 12);
        geoWeightCity = config.getInt("verification.geo.weights.city_weight", 6);
        geoDisallowHardAllowOnCountryMismatch = config.getBoolean("verification.geo.policy.disallowHardAllowOnCountryMismatch", true);
        geoAllowCountryMismatchForTrustHigh = config.getBoolean("verification.geo.policy.allowCountryMismatchForTrustHigh", true);

        // --- Load Messages ---
        String successMsg = config.getString("messages.protectionSuccess", "&a[NameGuard] Namamu sekarang dilindungi...");
        protectionSuccessMessage = (successMsg == null || successMsg.isEmpty()) ? Component.empty() : legacySerializer.deserialize(successMsg);

        // --- Load Debug ---
        logFailedAttempts = config.getBoolean("debug.logFailedAttempts", true);
    }

    /**
     * Builds the final kick message component.
     * @param reasonKey The key from config.yml (e.g., "hardMismatch")
     * @return The formatted Component to send to the player.
     */
    @NotNull
    public Component getKickMessage(@NotNull String reasonKey) {
        String reason = kickReasons.getOrDefault(reasonKey, "Alasan tidak diketahui.");
        String formattedMessage = rawKickMessage.replace("{reason}", reason);
        return legacySerializer.deserialize(formattedMessage);
    }

    // --- Getters for cached values ---

    public boolean isCrossEditionLock() {
        return crossEditionLock;
    }

    public int getRollingFpLimit() {
        return rollingFpLimit;
    }

    public long getFingerprintPurgeMillis() {
        return fingerprintPurgeMillis;
    }

    public int getScoreHardAllow() {
        return scoreHardAllow;
    }

    public int getScoreSoftAllow() {
        return scoreSoftAllow;
    }

    public int getWeightDeviceOs() {
        return weightDeviceOs;
    }

    public int getWeightBrand() {
        return weightBrand;
    }

    public int getWeightEdition() {
        return weightEdition;
    }

    public int getWeightSubnet() {
        return weightSubnet;
    }

    public int getWeightPseudoAsn() {
        return weightPseudoAsn;
    }

    public int getWeightPtrDomain() {
        return weightPtrDomain;
    }

    public int getWeightIpVersion() {
        return weightIpVersion;
    }

    // --- Strict verification getters (new) ---

    /**
     * If true, require at least some network overlap between new and old fingerprints
     * for an attempt to be considered legitimate.
     */
    public boolean isStrictRequireNetworkOverlap() {
        return strictRequireNetworkOverlap;
    }

    /**
     * Minimum number of matching network signals (prefix/ASN/PTR) required to be eligible
     * for hard allow. Recommended >= 1 to prevent client-only hard allow.
     */
    public int getStrictMinNetworkMatchesForHardAllow() {
        return strictMinNetworkMatchesForHardAllow;
    }

    /**
     * If true, trust HIGH or LOCKED bindings may bypass the zero-network-overlap restriction.
     */
    public boolean isStrictAllowZeroNetworkForTrustHigh() {
        return strictAllowZeroNetworkForTrustHigh;
    }

    // --- Ownership ---

    public long getTakeoverGracePeriodMillis() {
        return takeoverGracePeriodMillis;
    }

    public long getLowTrustPlaytimeMillis() {
        return lowTrustPlaytimeMillis;
    }

    // --- Security ---

    @NotNull
    public String getHmacSalt() {
        return hmacSalt;
    }

    // --- Rate limiting ---

    public boolean isRateLimitEnabled() {
        return rateLimitEnabled;
    }

    public int getRateLimitAttempts() {
        return rateLimitAttempts;
    }

    public long getRateLimitBlockDurationMillis() {
        return rateLimitBlockDurationMillis;
    }

    // --- Geo (new) ---

    public boolean isGeoEnabled() {
        return geoEnabled;
    }

    public int getGeoRequestTimeoutMillis() {
        return geoRequestTimeoutMillis;
    }

    public int getGeoCacheTtlMinutes() {
        return geoCacheTtlMinutes;
    }

    public int getGeoWeightCountry() {
        return geoWeightCountry;
    }

    public int getGeoWeightAsn() {
        return geoWeightAsn;
    }

    public int getGeoWeightCity() {
        return geoWeightCity;
    }

    public boolean isGeoDisallowHardAllowOnCountryMismatch() {
        return geoDisallowHardAllowOnCountryMismatch;
    }

    public boolean isGeoAllowCountryMismatchForTrustHigh() {
        return geoAllowCountryMismatchForTrustHigh;
    }

    // --- Messages ---

    @NotNull
    public Component getProtectionSuccessMessage() {
        return protectionSuccessMessage;
    }

    // --- Debug ---

    public boolean isLogFailedAttempts() {
        return logFailedAttempts;
    }

    /**
     * Gets the main plugin instance.
     * @return The NameGuard plugin instance.
     */
    @NotNull
    public NameGuard getPlugin() {
        return plugin;
    }
}
