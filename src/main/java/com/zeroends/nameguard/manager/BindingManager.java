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
    }

    @NotNull
    public LoginResult verifyLogin(@NotNull AsyncPlayerPreLoginEvent event) {
        String originalName = event.getName();
        String normalizedName = normalizationUtil.normalizeName(originalName);

        // Always reload from disk for the latest data!
        Binding binding = loadBinding(normalizedName).orElse(null);

        Fingerprint newFingerprint = fingerprintManager.createFingerprint(event);
        if (binding == null) {
            // Handle new binding creation
            binding = createNewBinding(normalizedName, originalName, newFingerprint);
            return new LoginResult.Allowed(binding, true, false);
        }

        binding.updateLastSeen();
        return handleExistingBinding(event, binding, newFingerprint);
    }

    @NotNull
    private Optional<Binding> loadBinding(@NotNull String normalizedName) {
        try {
            Optional<Binding> fromDisk = storage.loadBinding(normalizedName);
            fromDisk.ifPresent(binding -> bindingCache.put(normalizedName, binding));
            return fromDisk;
        } catch (Exception e) {
            plugin.getSLF4JLogger().error("I/O error when loading binding for {}: {}", normalizedName, e.getMessage());
            return Optional.empty();
        }
    }

    private Binding createNewBinding(String normalizedName, String originalName, Fingerprint newFingerprint) {
        String preferredName = stripLegacyPrefix(originalName);
        plugin.getSLF4JLogger().info(
                "Creating new binding for '{}': preferredName={}, normalized={}",
                originalName, preferredName, normalizedName
        );
        Binding binding = new Binding(normalizedName, preferredName, newFingerprint.getEdition(), newFingerprint);
        saveBinding(binding);
        return binding;
    }

    private LoginResult handleExistingBinding(
            AsyncPlayerPreLoginEvent event, Binding binding, Fingerprint newFingerprint) {
        // Match fingerprints and apply trust policies
        try {
            return processFingerprintMatches(event.getName(), binding, newFingerprint);
        } catch (Exception e) {
            plugin.getSLF4JLogger().error("Unexpected error during fingerprint evaluation: {}", 
            e.getMessage());
            return new LoginResult.Denied(event.getName(), component.RiskSerialiser)
        
        private Login DCancel
Berikut kode hasil perbaikannya untuk file `BindingManager.java`. 

```java name=src/main/java/com/zeroends/nameguard/manager/BindingManager.java url=https://github.com/AKSAHADIM/nameguard/blob/main/src/main/java/com/zeroends/nameguard/manager/BindingManager.java
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
 * Manages the core logic for creating, verifying, and persisting identity bindings.
 * PATCHES:
 * - Always flush fingerprints to disk immediately after verification.
 * - Always reload binding data from disk on login event.
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
        if (bindingCache.isEmpty()) {
            return;
        }
        plugin.getSLF4JLogger().info("Saving {} cached bindings to storage...", bindingCache.size());
        for (Object obj : bindingCache.values()) {
            if (obj instanceof Binding binding) {
                try {
                    binding.purgeOldFingerprints(configManager.getFingerprintPurgeMillis(), 1);
                    saveBindingToDisk(binding);
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
        Binding binding = getBindingOrLoad(normalizedName).orElse(null);

        Fingerprint newFingerprint = fingerprintManager.createFingerprint(event);

        if (binding == null) {
            return createNewBinding(normalizedName, originalName, newFingerprint);
        }

        binding.updateLastSeen();

        return evaluateBinding(binding, newFingerprint, originalName);
    }

    @NotNull
    private LoginResult createNewBinding(@NotNull String normalizedName, @NotNull String originalName,
                                         @NotNull Fingerprint newFingerprint) {
        String preferredName = removeLegacyPrefix(originalName);
        Binding newBinding = new Binding(normalizedName, preferredName, newFingerprint.getEdition(), newFingerprint);

        plugin.getSLF4JLogger().info(
                "Created new binding for '{}': displayName={}, normalizedName={}",
                originalName, preferredName, normalizedName
        );

        saveBindingToDisk(newBinding);
        return new LoginResult.Allowed(newBinding, true, false);
    }

    @NotNull
    private LoginResult evaluateBinding(
            @NotNull Binding binding,
            @NotNull Fingerprint newFingerprint,
            @NotNull String originalName
    ) {
        // Check if the binding matches the provided fingerprint.
        int trustLevel = verifyTrustOrCalculate(binding, newFingerprint);
        if (trustLevel < configManager.getScoreSoftAllow()) {
            return new LoginResult.Denied(
                    LoginResult.Reason.HARD_MISMATCH,
                    configManager.getKickMessage("hardMismatch")
            );
        }

        updateBindingFingerprint(binding, newFingerprint);
        return trustLevel >= configManager.getScoreHardAllow()
                ? new LoginResult.Allowed(binding, false, false)
                : new LoginResult.Allowed(binding, false, true);
    }

    private void updateBindingFingerprint(@NotNull Binding binding, @NotNull Fingerprint newFp) {
        binding.addFingerprint(newFp, configManager.getRollingFpLimit());
        saveBindingToDisk(binding);
    }

    private Optional<Binding> getBindingOrLoad(@NotNull String normalizedName) {
        return Optional.ofNullable(
                (Binding) bindingCache.computeIfAbsent(
                        normalizedName, key -> {
                            try {
                                return storage.loadBinding(key).orElse(null);
                            } catch (IOException e) {
                                plugin.getSLF4JLogger().error(
                                        "Failed to load binding for {}: {}",
                                        key, e.getMessage());
                                return null;
                            }
                        }
                )
        );
    }

    private @NotNull String removeLegacyPrefix(@NotNull String name) {
        return name.replaceFirst("^\\.+", "");
    }

    private int verifyTrustOrCalculate(
            @NotNull Binding existingBinding, @NotNull Fingerprint freshFinger) {
        return existingBinding.getFingerprints().stream()
                .map(fp -> fingerprintManager.getSimilarityDetailed(freshFinger, fp))
                .map(FingerprintManager.SimilarityResult::score)
                .max(Integer::compare)
                .orElse(0);
    }

    public void saveBinding(@NotNull Binding binding) {
        bindingCache.put(binding.getNormalizedName(), binding);
        saveBindingToDisk(binding);
    }

    private void saveBindingToDisk(@NotNull Binding binding) {
        try {
            storage.saveBinding(binding);
        } catch (IOException e) {
            plugin.getSLF4JLogger().error("Persist to disk failed for {}", binding.getNormalizedName());
        }
    }

    public @NotNull Map<String, Object> getBindingCache() {
        return bindingCache;
    }
}
