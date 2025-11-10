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
 * PATCH: Always flush new fingerprint to disk immediately after soft/hard allow and always reload binding from disk on login verification.
 */
public class BindingManager {

    private final NameGuard plugin;
    private final IStorage storage;
    private final NormalizationUtil normalizationUtil;
    private final FingerprintManager fingerprintManager;
    private final ConfigManager configManager;

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

    public void saveCacheToDisk() {
        plugin.getSLF4JLogger().info("Saving {} cached bindings to storage...", bindingCache.size());
        long purgeMillis = configManager.getFingerprintPurgeMillis();

        for (Object obj : bindingCache.values()) {
            if (obj instanceof Binding binding) {
                try {
                    if (purgeMillis > 0) {
                        binding.purgeOldFingerprints(purgeMillis, 1);
                    }
                    storage.saveBinding(binding);
                } catch (IOException e) {
                    plugin.getSLF4JLogger().error("Failed to save binding for: {}", binding.getNormalizedName(), e);
                }
            }
        }
        storage.shutdown();
    }

    @NotNull
    public LoginResult verifyLogin(@NotNull AsyncPlayerPreLoginEvent event) {
        String originalName = event.getName();
        String normalizedName = normalizationUtil.normalizeName(originalName);

        // Always reload from disk for the latest data!
        Binding binding = null;
        try {
            Optional<Binding> fromDisk = storage.loadBinding(normalizedName);
            if (fromDisk.isPresent()) {
                bindingCache.put(normalizedName, fromDisk.get());
                binding = fromDisk.get();
            } else {
                bindingCache.remove(normalizedName);
            }
        } catch (Exception e) {
            plugin.getSLF4JLogger().error("I/O error when loading binding from disk for {}", normalizedName, e);
        }

        String displayAttemptStripped = stripLegacyPrefix(originalName);

        try {
            Fingerprint newFingerprint = fingerprintManager.createFingerprint(event);
            AccountType attemptAccountType = newFingerprint.getEdition();

            if (binding != null) {
                binding.updateLastSeen();

                if (!equalsIgnoringLegacyPrefix(binding.getPreferredName(), originalName)) {
                    plugin.getSLF4JLogger().warn(
                            "Login denied for '{}' (normalized: {}): confusable spoof (expected display '{}').",
                            originalName, normalizedName, binding.getPreferredName()
                    );
                    return new LoginResult.Denied(
                            LoginResult.Reason.CONFUSABLE_NAME_SPOOF,
                            configManager.getKickMessage("confusableName")
                    );
                }

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

                double maxScore = -1;
                int bestNetworkMatches = 0;
                boolean strongIdentityOverride = false;

                for (Fingerprint oldFp : binding.getFingerprints()) {
                    FingerprintManager.SimilarityResult result =
                            fingerprintManager.getSimilarityDetailed(newFingerprint, oldFp);

                    if (result.strongIdentityConflict()) {
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

                boolean requireOverlap = configManager.isStrictRequireNetworkOverlap();
                int minMatchesForHardAllow = configManager.getStrictMinNetworkMatchesForHardAllow();
                boolean allowZeroForTrustHigh = configManager.isStrictAllowZeroNetworkForTrustHigh();
                Binding.TrustLevel trust = binding.getTrust();

                if (strongIdentityOverride) {
                    plugin.getSLF4JLogger().info(
                            "Hard allow (strong identity override) for '{}' (networkMatches={}).",
                            originalName, bestNetworkMatches
                    );
                    saveBinding(binding); // Persist to disk for every allow
                    return new LoginResult.Allowed(binding, false, false);
                }

                boolean trustBypass = allowZeroForTrustHigh &&
                        (trust == Binding.TrustLevel.HIGH || trust == Binding.TrustLevel.LOCKED);

                boolean networkEligibleForHard =
                        (!requireOverlap) ||
                                (bestNetworkMatches >= minMatchesForHardAllow) ||
                                trustBypass;

                if (!networkEligibleForHard && maxScore >= configManager.getScoreHardAllow()) {
                    plugin.getSLF4JLogger().info(
                            "Downgrading potential HARD_ALLOW for '{}' due to insufficient network matches (matches={}, minRequired={}, trustBypass={}).",
                            originalName, bestNetworkMatches, minMatchesForHardAllow, trustBypass
                    );
                    maxScore = configManager.getScoreHardAllow() - 1;
                }

                if (requireOverlap && bestNetworkMatches == 0 && !trustBypass && maxScore >= configManager.getScoreSoftAllow()) {
                    plugin.getSLF4JLogger().info(
                            "Rejecting SOFT_ALLOW for '{}' due to zero network overlap (score={}, softAllow={}, trustBypass={}).",
                            originalName, maxScore, configManager.getScoreSoftAllow(), trustBypass
                    );
                    maxScore = configManager.getScoreSoftAllow() - 1;
                }

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

                    if (!anyCountryMatch && !geoTrustBypass && maxScore >= configManager.getScoreHardAllow()) {
                        plugin.getSLF4JLogger().info(
                                "Downgrading HARD_ALLOW for '{}' due to country mismatch (newCountry={}, trust={}, allowBypass={}, hasMatch={}).",
                                originalName, newCountry, trust, configManager.isGeoAllowCountryMismatchForTrustHigh(), false
                        );
                        maxScore = configManager.getScoreHardAllow() - 1;
                    }
                }

                if (maxScore >= configManager.getScoreHardAllow()) {
                    plugin.getSLF4JLogger().info(
                            "Hard allow for '{}' (score={}, networkMatches={}, trust={}).",
                            originalName, maxScore, bestNetworkMatches, trust
                    );
                    String preferred = binding.getPreferredName();
                    if (!preferred.equals(stripLegacyPrefix(preferred))) {
                        binding.setPreferredName(stripLegacyPrefix(preferred));
                    }
                    saveBinding(binding);
                    return new LoginResult.Allowed(binding, false, false);
                }

                if (maxScore >= configManager.getScoreSoftAllow()) {
                    binding.addFingerprint(newFingerprint, configManager.getRollingFpLimit());
                    saveBinding(binding); // IMMEDIATELY persist fingerprint addition so it's not lost on quit/disconnect!
                    plugin.getSLF4JLogger().info(
                            "Soft allow for '{}' (score={}, networkMatches={}, trust={}, learned fingerprint).",
                            originalName, maxScore, bestNetworkMatches, trust
                    );
                    return new LoginResult.Allowed(binding, false, true);
                }

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
                // NEW binding: simpan preferredName tanpa prefix agar stabil ke depan.
                String preferredNoPrefix = stripLegacyPrefix(originalName);
                plugin.getSLF4JLogger().info(
                        "Creating new binding for '{}' (stored display '{}', edition={}, normalized={}).",
                        originalName, preferredNoPrefix, attemptAccountType, normalizedName
                );
                Binding newBinding = new Binding(normalizedName, preferredNoPrefix, attemptAccountType, newFingerprint);
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

    private boolean equalsIgnoringLegacyPrefix(String preferred, String attemptRaw) {
        if (preferred == null || attemptRaw == null) return false;
        String attemptStripped = stripLegacyPrefix(attemptRaw);
        return preferred.equals(attemptStripped);
    }

    private String stripLegacyPrefix(String name) {
        return name.replaceFirst("^\\.+", "");
    }

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

    public void saveBinding(@NotNull Binding binding) {
        Objects.requireNonNull(binding, "Binding cannot be null");
        bindingCache.put(binding.getNormalizedName(), binding);
        try {
            storage.saveBinding(binding);
        } catch (IOException e) {
            plugin.getSLF4JLogger().error("Failed to save binding for: {}", binding.getNormalizedName(), e);
        }
    }

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

    public boolean removeBinding(@NotNull String normalizedName) {
        Objects.requireNonNull(normalizedName, "Normalized name cannot be null");
        boolean inCache = bindingCache.remove(normalizedName) != null;
        try {
            storage.removeBinding(normalizedName);
            return true;
        } catch (IOException e) {
            plugin.getSLF4JLogger().error("Failed to remove binding for: {}", normalizedName, e);
            return false;
        }
    }

    public void reloadBindings() {
        saveCacheToDisk();
        bindingCache.clear();
    }

    @NotNull
    public Map<String, Object> getBindingCache() {
        return bindingCache;
    }
}
