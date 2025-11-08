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
 * This version (V3 Hybrid) uses a file-per-player storage model and an
 * in-memory cache for *online players only*.
 */
public class BindingManager {

    private final NameGuard plugin;
    private final IStorage storage;
    private final NormalizationUtil normalizationUtil;
    private final FingerprintManager fingerprintManager;
    private final ConfigManager configManager;
    
    // This cache now only holds bindings for players *currently online*
    private final Map<String, Object> bindingCache = new ConcurrentHashMap<>();

    public BindingManager(NameGuard plugin, IStorage storage, NormalizationUtil normalizationUtil, FingerprintManager fingerprintManager) {
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
                        binding.purgeOldFingerprints(purgeMillis, 1); // Selalu simpan minimal 1
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

        // Wrap logic in try-catch as getBinding() now performs I/O
        try {
            // 1. Create the new multi-factor fingerprint for this login attempt
            Fingerprint newFingerprint = fingerprintManager.createFingerprint(event);
            AccountType accountType = newFingerprint.getEdition();

            // 2. Get existing binding (from cache or load from disk)
            Optional<Binding> existingBindingOpt = getBinding(normalizedName);

            if (existingBindingOpt.isPresent()) {
                // --- KASUS: Nama sudah ada (Verifikasi) ---
                Binding binding = existingBindingOpt.get();
                binding.updateLastSeen();

                // Kasus 10: Spoof via casing/confusable
                if (!binding.getPreferredName().equals(originalName)) {
                    plugin.getSLF4JLogger().warn("Login denied for '{}' (normalized: {}): Attempted to use confusable name (real: {}).",
                            originalName, normalizedName, binding.getPreferredName());
                    return new LoginResult.Denied(
                            LoginResult.Reason.CONFUSABLE_NAME_SPOOF,
                            configManager.getKickMessage("confusableName")
                    );
                }
                
                // Kasus 4 & 5: Cek Cross-Edition Lock
                if (configManager.isCrossEditionLock() && binding.getAccountType() != accountType) {
                    plugin.getSLF4JLogger().warn("Login denied for '{}': Cross-edition lock active (Binding: {}, Attempt: {}).",
                            originalName, binding.getAccountType(), accountType);
                    return new LoginResult.Denied(
                            LoginResult.Reason.CROSS_EDITION_LOCK,
                            configManager.getKickMessage("crossEditionLock")
                    );
                }

                // --- Logika Skoring Multi-Faktor Baru ---
                double maxScore = 0.0;
                for (Fingerprint oldFp : binding.getFingerprints()) {
                    double score = fingerprintManager.getSimilarity(newFingerprint, oldFp);
                    if (score > maxScore) {
                        maxScore = score;
                    }
                }

                // 1. Hard Allow
                if (maxScore >= configManager.getScoreHardAllow()) {
                    return new LoginResult.Allowed(binding, false, false);
                }

                // 2. Soft Allow (Auto-Learning)
                if (maxScore >= configManager.getScoreSoftAllow()) {
                    binding.addFingerprint(newFingerprint, configManager.getRollingFpLimit());
                    saveBinding(binding); // Async save
                    return new LoginResult.Allowed(binding, false, true);
                }

                // 3. Deny
                plugin.getSLF4JLogger().warn("Login denied for '{}': Hard fingerprint mismatch (Max Score: {} < Threshold: {}).",
                        originalName, maxScore, configManager.getScoreSoftAllow());
                
                String adminMsgRaw = configManager.getPlugin().getConfig().getString("messages.adminMismatchNotify", "");
                if (adminMsgRaw != null && !adminMsgRaw.isEmpty()) {
                    Component adminMsg = Component.text(adminMsgRaw.replace("{player}", originalName));
                    plugin.getServer().broadcast(adminMsg, "nameguard.admin");
                }
                
                return new LoginResult.Denied(
                        LoginResult.Reason.HARD_MISMATCH,
                        configManager.getKickMessage("hardMismatch")
                );

            } else {
                // --- KASUS: Nama baru (Reservasi) ---
                plugin.getSLF4JLogger().info("Creating new binding for '{}' (Type: {}).", originalName, accountType);
                Binding newBinding = new Binding(normalizedName, originalName, accountType, newFingerprint);
                
                // Simpan binding baru ke disk dan cache
                saveBinding(newBinding);
                
                return new LoginResult.Allowed(newBinding, true, false);
            }
        
        } catch (IOException e) {
            plugin.getSLF4JLogger().error("I/O error during login verification for {}", event.getName(), e);
            return new LoginResult.Denied(
                    LoginResult.Reason.INTERNAL_ERROR,
                    configManager.getKickMessage("internalError")
            );
        }
    }

    /**
     * Gets a Binding. This is the core "load-on-demand" function.
     * 1. Check in-memory cache (RAM).
     * 2. If not in cache, try loading from storage (Disk).
     * 3. If loaded from Disk, add to cache.
     *
     * @param normalizedName The normalized name to search for.
     * @return An Optional containing the Binding if found.
     * @throws IOException If disk I/O fails during loading.
     */
    @NotNull
    @SuppressWarnings("unchecked")
    public Optional<Binding> getBinding(@NotNull String normalizedName) throws IOException {
        Objects.requireNonNull(normalizedName, "Normalized name cannot be null");
        
        // 1. Check RAM Cache
        Object data = bindingCache.get(normalizedName);

        if (data == null) {
            // 2. Not in RAM, try loading from Disk
            Optional<Binding> diskBinding = storage.loadBinding(normalizedName);
            
            if (diskBinding.isPresent()) {
                // 2a. Found on disk. Add to RAM cache.
                bindingCache.put(normalizedName, diskBinding.get());
                return diskBinding;
            } else {
                // 2b. Not on disk. Does not exist.
                return Optional.empty();
            }
        }

        // 3. Found in RAM. Handle failsafe and return.
        
        // FIX: Failsafe for ClassCastException (from old code, still useful)
        if (data instanceof Map) {
            plugin.getSLF4JLogger().warn("Found raw Map in cache for '{}'. Converting on-the-fly.", normalizedName);
            try {
                Binding convertedBinding = Binding.fromMap(normalizedName, (Map<String, Object>) data);
                bindingCache.put(normalizedName, convertedBinding); // Fix the cache
                return Optional.of(convertedBinding);
            } catch (Exception e) {
                plugin.getSLF4JLogger().error("Failed to convert raw Map to Binding for '{}'. Data is corrupt.", normalizedName, e);
                bindingCache.remove(normalizedName); // Remove corrupt data
                return Optional.empty();
            }
        }
        
        // It's already a Binding object
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
     * Saves the final state of a binding to disk, then removes it from the 
     * in-memory cache (RAM). Called on player quit.
     *
     * @param normalizedName The player to unload from the session cache.
     */
    public void unloadBinding(@NotNull String normalizedName) {
        Objects.requireNonNull(normalizedName, "Normalized name cannot be null");
        Object data = bindingCache.get(normalizedName);
        
        if (data instanceof Binding binding) {
            try {
                // Save final state (playtime, lastSeen, etc.) to disk
                storage.saveBinding(binding);
            } catch (IOException e) {
                plugin.getSLF4JLogger().error("Failed to save binding on unload for: {}", normalizedName, e);
            }
            
            // Remove from RAM cache
            bindingCache.remove(normalizedName);
        }
    }

    /**
     * Removes a binding from both the cache (RAM) and storage (Disk).
     * Used by /ng unbind command.
     */
    public boolean removeBinding(@NotNull String normalizedName) {
        Objects.requireNonNull(normalizedName, "Normalized name cannot be null");
        if (bindingCache.remove(normalizedName) != null) {
            try {
                storage.removeBinding(normalizedName);
                return true;
            } catch (IOException e) {
                plugin.getSLF4JLogger().error("Failed to remove binding for: {}", normalizedName, e);
                return false;
            }
        } else {
            // Not in cache, but might be on disk (e.g., offline player)
            try {
                storage.removeBinding(normalizedName); // Try deleting from disk anyway
                return true; // Assume success if no I/O error
            } catch (IOException e) {
                plugin.getSLF4JLogger().error("Failed to remove binding from disk for: {}", normalizedName, e);
                return false;
            }
        }
    }
    
    /**
     * Reloads the in-memory cache from storage.
     * In V3 Hybrid, this just saves and clears the cache.
     */
    public void reloadBindings() {
        this.saveCacheToDisk();
        this.bindingCache.clear();
    }
    
    /**
     * Returns the internal binding cache (online players only).
     * @return The map of bindings.
     */
    @NotNull
    public Map<String, Object> getBindingCache() {
        return bindingCache;
    }
}
