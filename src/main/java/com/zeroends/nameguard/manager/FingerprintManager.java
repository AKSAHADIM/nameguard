package com.zeroends.nameguard.manager;

import com.zeroends.nameguard.NameGuard;
import com.zeroends.nameguard.model.AccountType;
import com.zeroends.nameguard.model.Fingerprint;
import com.zeroends.nameguard.util.GeoIpUtil;
import com.zeroends.nameguard.util.IpHeuristicUtil;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.geysermc.floodgate.api.player.FloodgatePlayer;
import org.jetbrains.annotations.NotNull;

import java.net.InetAddress;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Manages the creation and comparison of multi-factor fingerprints.
 *
 * V4 Enhancements:
 *  - Adds optional Geo-IP enrichment (countryCode, region, city, asn, org, isp) via GeoIpUtil.
 *  - Adds geo-based scoring (country / ASN / city) to similarity calculation.
 *  - Still keeps network match counting (subnet / pseudo ASN / PTR) for strict gating in BindingManager.
 *
 * Design Notes:
 *  - Geo scoring is additive ONLY; policy-level downgrades (e.g. "disallow hard allow on country mismatch")
 *    are applied in BindingManager after evaluating all historic fingerprints.
 *  - Strong identity (XUID) override / conflict logic stays highest precedence.
 */
public class FingerprintManager {

    private final NameGuard plugin;
    private final ConfigManager configManager;
    private final IpHeuristicUtil ipHeuristicUtil;
    private final GeoIpUtil geoIpUtil; // optional (may be enabled/disabled in config)

    public FingerprintManager(NameGuard plugin,
                              @NotNull IpHeuristicUtil ipHeuristicUtil,
                              @NotNull GeoIpUtil geoIpUtil) {
        this.plugin = plugin;
        this.configManager = plugin.getConfigManager();
        this.ipHeuristicUtil = ipHeuristicUtil;
        this.geoIpUtil = geoIpUtil;
    }

    /**
     * Creates a new, multi-factor Fingerprint for a connecting player.
     *
     * @param event The login event containing player data.
     * @return A new Fingerprint object.
     */
    @NotNull
    public Fingerprint createFingerprint(@NotNull AsyncPlayerPreLoginEvent event) {
        InetAddress ip = event.getAddress();

        Optional<FloodgatePlayer> floodgatePlayerOpt = plugin.getFloodgateApi()
                .map(api -> api.getPlayer(event.getUniqueId()));

        AccountType edition = floodgatePlayerOpt.isPresent() ? AccountType.BEDROCK : AccountType.JAVA;

        Fingerprint.Builder builder = Fingerprint.builder().edition(edition);

        // --- 1. Network Signals (Heuristics V3) ---

        // IP Version
        String ipVersion = ipHeuristicUtil.getIpVersion(ip);
        builder.ipVersion(ipVersion);

        // Subnet Prefix
        String prefix = ipHeuristicUtil.getSubnetPrefix(ip);
        if (prefix != null) {
            builder.hashedPrefix(ipHeuristicUtil.hmacSha256(prefix));
        }

        // Pseudo ASN
        String pseudoAsn = ipHeuristicUtil.getPseudoAsn(ip);
        if (pseudoAsn != null) {
            builder.hashedPseudoAsn(ipHeuristicUtil.hmacSha256(pseudoAsn));
        }

        // PTR Domain (Reverse DNS) - Asynchronously (best-effort)
        try {
            String ptr = ipHeuristicUtil.getPTR(ip).get(1, TimeUnit.SECONDS);
            if (ptr != null) {
                builder.hashedPtr(ipHeuristicUtil.hmacSha256(ptr));
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            // Ignore failure or timeout, PTR lookup is secondary
        }

        // --- 2. Client & Identity Signals ---
        if (floodgatePlayerOpt.isPresent()) {
            FloodgatePlayer fp = floodgatePlayerOpt.get();
            builder.clientBrand("geyser");
            builder.xuid(fp.getXuid());          // Strong identity for Bedrock
            builder.deviceOs(fp.getDeviceOs().name());
            builder.protocolVersion(fp.getVersion());
        } else {
            // Java Player
            builder.clientBrand("java");
            builder.javaUuid(event.getUniqueId().toString());
            // Protocol version not available here (needs handshake listener)
        }

        // --- 3. Geo-IP Enrichment (Optional) ---
        // Safe to call even if disabled; GeoIpUtil will no-op when geo.enabled=false.
        geoIpUtil.enrichFingerprint(ip, builder);

        return builder.build();
    }

    /**
     * Legacy simple similarity scoring retained for backward compatibility.
     * Does NOT apply strict gating or penalties—only raw additive scoring.
     * Prefer {@link #getSimilarityDetailed(Fingerprint, Fingerprint)} for new logic.
     */
    public int getSimilarity(@NotNull Fingerprint newFp, @NotNull Fingerprint oldFp) {
        return getSimilarityDetailed(newFp, oldFp).score();
    }

    /**
     * Calculates a detailed similarity result between two fingerprints.
     * Returns both the raw score (before any external gating) and the count of matching network signals.
     *
     * Network signals counted:
     *  - Subnet Prefix (hashedPrefix)
     *  - Pseudo ASN (hashedPseudoAsn)
     *  - PTR Domain (hashedPtr)
     *
     * Geo signals (if enabled) scored additively:
     *  - Country Code
     *  - ASN (numeric, plain text from resolver)
     *  - City (or region) depending on config
     *
     * Gating / policy (e.g., disallowHardAllowOnCountryMismatch) is applied in BindingManager.
     *
     * Strong Identity Override:
     *  - If XUID matches: returns score = (hard_allow + 10), networkMatches computed but policy gating is skipped externally.
     *  - If XUID mismatch (both present, different): returns score = 0, networkMatches = 0.
     *
     * @param newFp current login fingerprint
     * @param oldFp stored historical fingerprint
     * @return SimilarityResult containing raw score and network match count
     */
    public SimilarityResult getSimilarityDetailed(@NotNull Fingerprint newFp, @NotNull Fingerprint oldFp) {

        // --- 1. Strong Identity (Bedrock XUID) ---
        if (newFp.getXuid() != null && Objects.equals(newFp.getXuid(), oldFp.getXuid())) {
            int overrideScore = configManager.getScoreHardAllow() + 10;
            int nm = countNetworkMatches(newFp, oldFp);
            return new SimilarityResult(overrideScore, nm, true, false);
        }
        if (newFp.getXuid() != null && oldFp.getXuid() != null && !newFp.getXuid().equals(oldFp.getXuid())) {
            // Explicit mismatch -> immediate failure
            return new SimilarityResult(0, 0, false, true);
        }

        int score = 0;

        // --- 2. Client & Edition Signals ---
        if (Objects.equals(newFp.getDeviceOs(), oldFp.getDeviceOs())) {
            score += configManager.getWeightDeviceOs();
        }
        if (Objects.equals(newFp.getClientBrand(), oldFp.getClientBrand())) {
            score += configManager.getWeightBrand();
        }
        if (Objects.equals(newFp.getEdition(), oldFp.getEdition())) {
            score += configManager.getWeightEdition();
        }
        if (Objects.equals(newFp.getIpVersion(), oldFp.getIpVersion())) {
            score += configManager.getWeightIpVersion();
        }

        // --- 3. Network Heuristic Signals ---
        int networkMatches = 0;

        if (Objects.equals(newFp.getHashedPrefix(), oldFp.getHashedPrefix())) {
            score += configManager.getWeightSubnet();
            networkMatches++;
        }
        if (Objects.equals(newFp.getHashedPseudoAsn(), oldFp.getHashedPseudoAsn())) {
            score += configManager.getWeightPseudoAsn();
            networkMatches++;
        }
        if (Objects.equals(newFp.getHashedPtr(), oldFp.getHashedPtr())) {
            score += configManager.getWeightPtrDomain();
            networkMatches++;
        }

        // --- 4. Geo Scoring (Optional Additive) ---
        if (configManager.isGeoEnabled()) {
            // Country code equality
            if (isNonEmptyEqual(newFp.getCountryCode(), oldFp.getCountryCode())) {
                score += configManager.getGeoWeightCountry();
            }
            // ASN (raw numeric/string from resolver)
            if (isNonEmptyEqual(newFp.getAsn(), oldFp.getAsn())) {
                score += configManager.getGeoWeightAsn();
            }
            // City (or region) match
            boolean cityMatched = isNonEmptyEqual(newFp.getCity(), oldFp.getCity());
            if (!cityMatched) {
                // Fallback: if city not available on either side, try region
                if (isNonEmptyEqual(newFp.getRegion(), oldFp.getRegion())) {
                    cityMatched = true;
                }
            }
            if (cityMatched) {
                score += configManager.getGeoWeightCity();
            }
        }

        return new SimilarityResult(score, networkMatches, false, false);
    }

    private boolean isNonEmptyEqual(String a, String b) {
        return a != null && b != null && !a.isEmpty() && !b.isEmpty() && a.equals(b);
    }

    /**
     * Helper to count network signal matches (without affecting score).
     */
    private int countNetworkMatches(@NotNull Fingerprint a, @NotNull Fingerprint b) {
        int matches = 0;
        if (Objects.equals(a.getHashedPrefix(), b.getHashedPrefix())) matches++;
        if (Objects.equals(a.getHashedPseudoAsn(), b.getHashedPseudoAsn())) matches++;
        if (Objects.equals(a.getHashedPtr(), b.getHashedPtr())) matches++;
        return matches;
    }

    /**
     * Immutable container for similarity evaluation.
     */
    public record SimilarityResult(
            int score,
            int networkMatches,
            boolean strongIdentityOverride,
            boolean strongIdentityConflict
    ) {
        public boolean hasAnyNetworkMatch() {
            return networkMatches > 0;
        }
    }
}
