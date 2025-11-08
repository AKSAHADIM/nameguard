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
 * This version uses local heuristic scoring (V3).
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

        // PTR Domain (Reverse DNS) - Asynchronously
        try {
            String ptr = ipHeuristicUtil.getPTR(ip).get(1, TimeUnit.SECONDS);
            if (ptr != null) {
                // Hashing the domain for privacy
                builder.hashedPtr(ipHeuristicUtil.hmacSha256(ptr));
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            // Ignore failure or timeout, PTR lookup is secondary
        }


        // --- 2. Client & Identity Signals ---
        if (floodgatePlayerOpt.isPresent()) {
            FloodgatePlayer fp = floodgatePlayerOpt.get();
            builder.clientBrand("geyser");
            builder.xuid(fp.getXuid()); // Kuat
            builder.deviceOs(fp.getDeviceOs().name());
            builder.protocolVersion(fp.getVersion());
        } else {
            // Java Player
            builder.clientBrand("java"); 
            builder.javaUuid(event.getUniqueId().toString()); 
            // Protocol version is unavailable at this stage
        }

        return builder.build();
    }
    
    /**
     * Calculates the similarity score between two multi-factor fingerprints based on V3 heuristic weights.
     *
     * @param newFp The new (current login) fingerprint.
     * @param oldFp The old (stored) fingerprint.
     * @return A similarity score (0 to 100+).
     */
    public int getSimilarity(@NotNull Fingerprint newFp, @NotNull Fingerprint oldFp) {
        
        // --- 1. Identitas Kuat (Hard Identity) ---
        // XUID cocok = 100% (Hard Allow)
        if (newFp.getXuid() != null && Objects.equals(newFp.getXuid(), oldFp.getXuid())) {
            return configManager.getScoreHardAllow() + 10; // Pastikan skor melewati HardAllow threshold
        }
        
        // Jika XUID baru ada tapi TIDAK COCOK dengan XUID lama, ini adalah peniru
        if (newFp.getXuid() != null && oldFp.getXuid() != null && !newFp.getXuid().equals(oldFp.getXuid())) {
             return 0;
        }

        int score = 0;
        
        // --- 2. Sinyal Klien & Edisi (Bobot Tinggi) ---
        if (Objects.equals(newFp.getDeviceOs(), oldFp.getDeviceOs())) {
            score += configManager.getWeightDeviceOs();
        }
        
        if (Objects.equals(newFp.getClientBrand(), oldFp.getClientBrand())) {
            score += configManager.getWeightBrand();
        }
        
        if (Objects.equals(newFp.getEdition(), oldFp.getEdition())) {
            score += configManager.getWeightEdition();
        }
        
        // --- 3. Sinyal Jaringan Heuristik (Bobot Menengah) ---
        if (Objects.equals(newFp.getHashedPrefix(), oldFp.getHashedPrefix())) {
            score += configManager.getWeightSubnet();
        }
        
        if (Objects.equals(newFp.getHashedPseudoAsn(), oldFp.getHashedPseudoAsn())) {
            score += configManager.getWeightPseudoAsn();
        }
        
        if (Objects.equals(newFp.getHashedPtr(), oldFp.getHashedPtr())) {
            score += configManager.getWeightPtrDomain();
        }

        if (Objects.equals(newFp.getIpVersion(), oldFp.getIpVersion())) {
            score += configManager.getWeightIpVersion();
        }
        
        return score;
    }
}
