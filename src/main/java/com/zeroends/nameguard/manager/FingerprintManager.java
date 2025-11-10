package com.zeroends.nameguard.manager;

import com.zeroends.nameguard.NameGuard;
import com.zeroends.nameguard.model.AccountType;
import com.zeroends.nameguard.model.Fingerprint;
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
 * Enhanced (Strict Mode capable) version:
 *  - Adds network match counting (subnet / pseudo ASN / PTR).
 *  - Provides detailed similarity result to allow gating logic in BindingManager.
 */
public class FingerprintManager {

    private final NameGuard plugin;
    private final ConfigManager configManager;
    private final IpHeuristicUtil ipHeuristicUtil;

    public FingerprintManager(NameGuard plugin, @NotNull IpHeuristicUtil ipHeuristicUtil) {
        this.plugin = plugin;
        this.configManager = plugin.getConfigManager();
        this.ipHeuristicUtil = ipHeuristicUtil;
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
     * Gating / penalties are NOT enforced here; they are handled by BindingManager
     * using the returned networkMatches plus trust level and strict config flags.
     *
     * Strong Identity Override:
     *  - If XUID matches: returns score = (hard_allow + 10), networkMatches computed but irrelevant for allow.
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

        // --- 2. Client & Edition Signals (High weight group) ---
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

        // --- 3. Network Heuristic Signals (Medium weight group) ---
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

        return new SimilarityResult(score, networkMatches, false, false);
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
