package com.zeroends.nameguard.manager;

import com.zeroends.nameguard.NameGuard;
import com.zeroends.nameguard.model.AccountType;
import com.zeroends.nameguard.model.Binding;
import com.zeroends.nameguard.model.Fingerprint;
import com.zeroends.nameguard.model.LoginResult;
import com.zeroends.nameguard.storage.IStorage;
import com.zeroends.nameguard.util.NormalizationUtil;
import net.kyori.adventure.text.Component;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages the core logic of creating, verifying, and persisting identity bindings.
 * Enhanced for:
 *  - Strict Network Gating (require overlap for hard allow, optional soft gating).
 *  - Geo policy gating (optional): disallow hard-allow when country mismatches historical fingerprints,
 *    with optional bypass for HIGH/LOCKED trust.
 */
public class BindingManager {

    private final NameGuard plugin;
    private final IStorage storage;
    private final NormalizationUtil normalizationUtil;
    private final FingerprintManager fingerprintManager;
    private final ConfigManager configManager;

    // This cache now only holds bindings for players *currently online*
    private final Map<String, Object> bindingCache = new ConcurrentHashMap<>();

    public BindingManager(NameGuard plugin,
                          IStorage storage,
                          NormalizationUtil normalizationUtil,
                          FingerprintManager fingerprintManager) {
        this.plugin = plugin;
        this.storage = storage;
        this.normalizationUtil = normalizationUtil;
        this.fingerprintManager = fingerprintManager;
        this.configManager = plugin.getConfigManager();
    }

    /**
     * Saves all currently cached (online) bindings back to storage.
     * Used on plugin disable.
     */
    public void saveCacheToDisk() {
        plugin.getSLF4JLogger().info("Saving {} cached bindings to storage...", bindingCache.size());
        long purgeMillis = configManager.getFingerprintPurgeMillis();

        for (Object obj : bindingCache.values()) {
            if (obj instanceof Binding binding) {
                try {
                    // Auto-purge old fingerprints before saving
                    if (purgeMillis > 0) {
                        binding.purgeOldFingerprints(purgeMillis, 1); // Always keep at least 1
                    }
                    storage.saveBinding(binding);
                } catch (IOException e) {
                    plugin.getSLF4JLogger().error("Failed to save binding for: {}", binding.getNormalizedName(), e);
                }
            }
        }
        storage.shutdown();
    }

    /**
     * The main verification logic called during AsyncPlayerPreLoginEvent.
     *
     * @param event The login event.
     * @return A LoginResult (Allowed or Denied).
     */
    @NotNull
    public LoginResult verifyLogin(@NotNull AsyncPlayerPreLoginEvent event) {
        String originalName = event.getName();
        String normalizedName = normalizationUtil.normalizeName(originalName);

        try {
            // 1. Create the new multi-factor fingerprint for this login attempt
            Fingerprint newFingerprint = fingerprintManager.createFingerprint(event);
            AccountType attemptAccountType = newFingerprint.getEdition();

            // 2. Get existing binding (from cache or load from disk)
            Optional<Binding> existingBindingOpt = getBinding(normalizedName);

            if (existingBindingOpt.isPresent()) {
                // --- EXISTING NAME (Verification Path) ---
                Binding binding = existingBindingOpt.get();
                binding.updateLastSeen();

                // Spoof via casing/confusable attempt
                if (!binding.getPreferredName().equals(originalName)) {
                    plugin.getSLF4JLogger().warn(
                            "Login denied for '{}' (normalized: {}): confusable spoof (expected display '{}').",
                            originalName, normalizedName, binding.getPreferredName()
                    );
                    return new LoginResult.Denied(
                            LoginResult.Reason.CONFUSABLE_NAME_SPOOF,
                            configManager.getKickMessage("confusableName")
                    );
                }

                // Cross edition lock
                if (configManager.isCrossEditionLock() && binding.getAccountType() != attemptAccountType) {
                    plugin.getSLF4JLogger().warn(
                            "Login denied for '{}': crossEditionLock active (binding: {}, attempt: {}).",
                            originalName, binding.getAccountType(), attemptAccountType
                    );
                    return new LoginResult.Denied(
                            LoginResult.Reason.CROSS_EDITION_LOCK,
                            configManager.getKickMessage("crossEditionLock")
                    );
                }

                // --- Similarity Scoring with detailed network match accounting ---
                double maxScore = -1;
                int bestNetworkMatches = 0;
                boolean strongIdentityOverride = false;
                boolean strongIdentityConflict = false;

                for (Fingerprint oldFp : binding.getFingerprints()) {
                    FingerprintManager.SimilarityResult result =
                            fingerprintManager.getSimilarityDetailed(newFingerprint, oldFp);

                    if (result.strongIdentityConflict()) {
                        // Immediate denial due to conflicting strong identity (Bedrock XUID mismatch)
                        plugin.getSLF4JLogger().warn(
                                "Login denied for '{}': strong identity conflict (XUID mismatch).",
                                originalName
                        );
                        return new LoginResult.Denied(
                                LoginResult.Reason.HARD_MISMATCH,
                                configManager.getKickMessage("hardMismatch")
                        );
                    }

                    if (result.score() > maxScore) {
                        maxScore = result.score();
                        bestNetworkMatches = result.networkMatches();
                        strongIdentityOverride = result.strongIdentityOverride();
                    }
                }

                // --- Strict Network Gating Logic ---
                boolean requireOverlap = configManager.isStrictRequireNetworkOverlap();
                int minMatchesForHardAllow = configManager.getStrictMinNetworkMatchesForHardAllow();
                boolean allowZeroForTrustHigh = configManager.isStrictAllowZeroNetworkForTrustHigh();
                Binding.TrustLevel trust = binding.getTrust();

                // If we have a strong identity (Bedrock XUID match), bypass gating
                if (strongIdentityOverride) {
                    plugin.getSLF4JLogger().info(
                            "Hard allow (strong identity override) for '{}' (XUID match, networkMatches={}).",
                            originalName, bestNetworkMatches
                    );
                    return new LoginResult.Allowed(binding, false, false);
                }

                // Determine if trust qualifies for zero-network-match bypass
                boolean trustBypass = allowZeroForTrustHigh &&
                        (trust == Binding.TrustLevel.HIGH || trust == Binding.TrustLevel.LOCKED);

                // Apply network gating BEFORE classification into hard/soft/deny
                boolean networkEligibleForHard =
                        (!requireOverlap) ||
                        (bestNetworkMatches >= minMatchesForHardAllow) ||
                        trustBypass;

                if (!networkEligibleForHard) {
                    // Not eligible for hard allow. If score would have been >= hardAllow, force downgrade.
                    if (maxScore >= configManager.getScoreHardAllow()) {
                        plugin.getSLF4JLogger().info(
                                "Downgrading potential HARD_ALLOW for '{}' due to insufficient network matches (matches={}, minRequired={}, trustBypass={}).",
                                originalName, bestNetworkMatches, minMatchesForHardAllow, trustBypass
                        );
                        // Force treat as soft or deny by setting maxScore just below hard threshold
                        maxScore = configManager.getScoreHardAllow() - 1;
                    }
                }

                // Optional gating for soft allow: if absolutely zero network matches and not bypassed, deny.
                if (requireOverlap && bestNetworkMatches == 0 && !trustBypass) {
                    if (maxScore >= configManager.getScoreSoftAllow()) {
                        plugin.getSLF4JLogger().info(
                                "Rejecting SOFT_ALLOW for '{}' due to zero network overlap (score={}, softAllow={}, trustBypass={}).",
                                originalName, maxScore, configManager.getScoreSoftAllow(), trustBypass
                        );
                        // Force below soft allow
                        maxScore = configManager.getScoreSoftAllow() - 1;
                    }
                }

                // --- Geo Policy Gating (Optional) ---
                // Disallow HARD allow when the new attempt's countryCode does not match ANY historical fingerprint's country,
                // unless bypass allowed for HIGH/LOCKED trust.
                if (configManager.isGeoEnabled() && configManager.isGeoDisallowHardAllowOnCountryMismatch()) {
                    boolean anyCountryMatch = false;
                    String newCountry = newFingerprint.getCountryCode();
                    if (newCountry != null && !newCountry.isEmpty()) {
                        for (Fingerprint oldFp : binding.getFingerprints()) {
                            String oldCountry = oldFp.getCountryCode();
                            if (oldCountry != null && !oldCountry.isEmpty() && newCountry.equals(oldCountry)) {
                                anyCountryMatch = true;
                                break;
                            }
                        }
                    }
                    boolean geoTrustBypass = configManager.isGeoAllowCountryMismatchForTrustHigh()
                            && (trust == Binding.TrustLevel.HIGH || trust == Binding.TrustLevel.LOCKED);

                    if (!anyCountryMatch && !geoTrustBypass) {
                        if (maxScore >= configManager.getScoreHardAllow()) {
                            plugin.getSLF4JLogger().info(
                                    "Downgrading potential HARD_ALLOW for '{}' due to country mismatch (newCountry={}, trust={}, allowBypassForHigh={}, hasMatch={}).",
                                    originalName, newCountry, trust, configManager.isGeoAllowCountryMismatchForTrustHigh(), false
                            );
                            maxScore = configManager.getScoreHardAllow() - 1;
                        }
                    }
                }

                // --- Classification after gating adjustments ---

                if (maxScore >= configManager.getScoreHardAllow()) {
                    plugin.getSLF4JLogger().info(
                            "Hard allow for '{}' (score={}, networkMatches={}, trust={}).",
                            originalName, maxScore, bestNetworkMatches, trust
                    );
                    return new LoginResult.Allowed(binding, false, false);
                }

                if (maxScore >= configManager.getScoreSoftAllow()) {
                    // Auto-learning: add new fingerprint if rolling limit not exceeded
                    binding.addFingerprint(newFingerprint, configManager.getRollingFpLimit());
                    saveBinding(binding); // Persist updated binding
                    plugin.getSLF4JLogger().info(
                            "Soft allow for '{}' (score={}, networkMatches={}, trust={}, learned fingerprint).",
                            originalName, maxScore, bestNetworkMatches, trust
                    );
                    return new LoginResult.Allowed(binding, false, true);
                }

                // Deny (Hard mismatch)
                plugin.getSLF4JLogger().warn(
                        "Login denied for '{}': mismatch (score={}, softAllow={}, networkMatches={}, trust={}, overlapRequired={}).",
                        originalName, maxScore, configManager.getScoreSoftAllow(), bestNetworkMatches, trust, requireOverlap
                );

                String adminMsgRaw = configManager.getPlugin().getConfig()
                        .getString("messages.adminMismatchNotify", "");
                if (adminMsgRaw != null && !adminMsgRaw.isEmpty()) {
                    Component adminMsg = Component.text(adminMsgRaw.replace("{player}", originalName));
                    plugin.getServer().broadcast(adminMsg, "nameguard.admin");
                }

                return new LoginResult.Denied(
                        LoginResult.Reason.HARD_MISMATCH,
                        configManager.getKickMessage("hardMismatch")
                );

            } else {
                // --- NEW NAME (Reservation Path) ---
                plugin.getSLF4JLogger().info(
                        "Creating new binding for '{}' (edition={}, normalized={}).",
                        originalName, attemptAccountType, normalizedName
                );
                Binding newBinding = new Binding(normalizedName, originalName, attemptAccountType, newFingerprint);
                saveBinding(newBinding);
                return new LoginResult.Allowed(newBinding, true, false);
            }

        } catch (IOException e) {
            plugin.getSLF4JLogger().error("I/O error during login verification for {}", event.getName(), e);
            return new LoginResult.Denied(
                    LoginResult.Reason.INTERNAL_ERROR,
                    configManager.getKickMessage("internalError")
            );
        } catch (Exception e) {
            plugin.getSLF4JLogger().error("Unexpected error during verification for {}", event.getName(), e);
            return new LoginResult.Denied(
                    LoginResult.Reason.INTERNAL_ERROR,
                    configManager.getKickMessage("internalError")
            );
        }
    }

    /**
     * Gets a Binding. Load-on-demand:
     * 1. Check RAM cache.
     * 2. Load from storage if absent.
     * 3. Convert legacy map structures if needed.
     *
     * @param normalizedName The normalized name to search for.
     * @return Optional binding.
     * @throws IOException If disk I/O fails.
     */
    @NotNull
    @SuppressWarnings("unchecked")
    public Optional<Binding> getBinding(@NotNull String normalizedName) throws IOException {
        Objects.requireNonNull(normalizedName, "Normalized name cannot be null");

        Object data = bindingCache.get(normalizedName);

        if (data == null) {
            Optional<Binding> diskBinding = storage.loadBinding(normalizedName);
            if (diskBinding.isPresent()) {
                bindingCache.put(normalizedName, diskBinding.get());
                return diskBinding;
            }
            return Optional.empty();
        }

        // Failsafe for legacy raw map entry
        if (data instanceof Map) {
            plugin.getSLF4JLogger().warn("Found raw Map in cache for '{}'. Converting...", normalizedName);
            try {
                Binding convertedBinding = Binding.fromMap(normalizedName, (Map<String, Object>) data);
                bindingCache.put(normalizedName, convertedBinding);
                return Optional.of(convertedBinding);
            } catch (Exception e) {
                plugin.getSLF4JLogger().error(
                        "Failed to convert raw Map to Binding for '{}'. Data corrupt - removing.",
                        normalizedName, e
                );
                bindingCache.remove(normalizedName);
                return Optional.empty();
            }
        }

        return Optional.of((Binding) data);
    }

    /**
     * Saves a binding to both the cache (RAM) and storage (Disk).
     * @param binding The binding to save.
     */
    public void saveBinding(@NotNull Binding binding) {
        Objects.requireNonNull(binding, "Binding cannot be null");
        bindingCache.put(binding.getNormalizedName(), binding);
        try {
            storage.saveBinding(binding);
        } catch (IOException e) {
            plugin.getSLF4JLogger().error("Failed to save binding for: {}", binding.getNormalizedName(), e);
        }
    }

    /**
     * Saves final state then removes from in-memory cache (called on quit).
     * @param normalizedName Player normalized name.
     */
    public void unloadBinding(@NotNull String normalizedName) {
        Objects.requireNonNull(normalizedName, "Normalized name cannot be null");
        Object data = bindingCache.get(normalizedName);

        if (data instanceof Binding binding) {
            try {
                storage.saveBinding(binding);
            } catch (IOException e) {
                plugin.getSLF4JLogger().error("Failed to save binding on unload for: {}", normalizedName, e);
            }
            bindingCache.remove(normalizedName);
        }
    }

    /**
     * Removes a binding from cache and storage (/ng unbind).
     * @param normalizedName The normalized name.
     * @return true if removed (either from cache or disk), false if error.
     */
    public boolean removeBinding(@NotNull String normalizedName) {
        Objects.requireNonNull(normalizedName, "Normalized name cannot be null");
        boolean inCache = bindingCache.remove(normalizedName) != null;
        try {
            storage.removeBinding(normalizedName);
            return true;
        } catch (IOException e) {
            plugin.getSLF4JLogger().error("Failed to remove binding for: {}", normalizedName, e);
            // If it was in cache but disk removal failed, treat as failure
            return false;
        }
    }

    /**
     * Reload logic for hybrid model: flush & clear cache.
     */
    public void reloadBindings() {
        saveCacheToDisk();
        bindingCache.clear();
    }

    /**
     * Returns internal binding cache (online players only).
     */
    @NotNull
    public Map<String, Object> getBindingCache() {
        return bindingCache;
    }
}
