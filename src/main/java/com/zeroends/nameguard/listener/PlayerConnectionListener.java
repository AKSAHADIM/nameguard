package com.zeroends.nameguard.listener;

import com.zeroends.nameguard.NameGuard;
import com.zeroends.nameguard.manager.BindingManager;
import com.zeroends.nameguard.manager.ConfigManager;
import com.zeroends.nameguard.model.Binding;
import com.zeroends.nameguard.model.LoginResult;
import net.kyori.adventure.text.Component;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Listens for player connection events (login, join, quit)
 * to apply identity verification and manage session data (Hybrid Model).
 */
public class PlayerConnectionListener implements Listener {

    private final NameGuard plugin;
    private final BindingManager bindingManager;
    private final ConfigManager configManager;
    private final ConcurrentHashMap<String, Object> loginLocks;
    
    // Simple in-memory map to track session start times for playtime calculation
    private final ConcurrentHashMap<String, Long> sessionStartTime = new ConcurrentHashMap<>();
    
    // Set to track new bindings across async/sync events
    private final Set<String> newBindings = ConcurrentHashMap.newKeySet();

    public PlayerConnectionListener(NameGuard plugin) {
        this.plugin = plugin;
        this.bindingManager = plugin.getBindingManager();
        this.configManager = plugin.getConfigManager();
        this.loginLocks = plugin.getLoginLocks();
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onAsyncPlayerPreLogin(AsyncPlayerPreLoginEvent event) {
        if (event.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) {
            return; // Already denied by another plugin
        }

        String normalizedName = plugin.getNormalizationUtil().normalizeName(event.getName());
        
        // Dapatkan lock untuk nama yang dinormalisasi ini
        Object lock = loginLocks.computeIfAbsent(normalizedName, k -> new Object());

        synchronized (lock) {
            try {
                // Verifikasi login (sekarang bisa memicu I/O via BindingManager)
                LoginResult result = bindingManager.verifyLogin(event);

                if (result instanceof LoginResult.Denied deniedResult) {
                    // Login ditolak
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                            Objects.requireNonNullElse(deniedResult.kickMessage(), Component.text("Login ditolak.")));
                    
                    if (configManager.isLogFailedAttempts()) {
                        plugin.getSLF4JLogger().warn("Denied login for {}: {} (IP: {})",
                                event.getName(), deniedResult.reason(), event.getAddress().getHostAddress());
                    }
                    
                } else if (result instanceof LoginResult.Allowed allowedResult) {
                    // Login diizinkan
                    // Catat waktu mulai sesi untuk perhitungan playtime
                    sessionStartTime.put(normalizedName, System.currentTimeMillis());

                    // Tandai untuk mengirim pesan selamat datang jika binding baru
                    if (allowedResult.isNewBinding()) {
                        // Simpan nama ini untuk PlayerJoinEvent (yang berjalan di main thread)
                        newBindings.add(normalizedName);
                    }
                }

            } catch (Exception e) {
                // Tangani error I/O dari BindingManager atau error lainnya
                plugin.getSLF4JLogger().error("Error during login verification for {}", event.getName(), e);
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        configManager.getKickMessage("internalError"));
            } finally {
                // Selalu lepaskan lock setelah selesai
                loginLocks.remove(normalizedName);
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        String normalizedName = plugin.getNormalizationUtil().normalizeName(event.getPlayer().getName());
        
        // Cek apakah ini binding baru (dari hasil verifikasi async)
        if (newBindings.remove(normalizedName)) {
            // Ini adalah binding baru, kirim pesan sukses
            if (!configManager.getProtectionSuccessMessage().equals(Component.empty())) {
                event.getPlayer().sendMessage(configManager.getProtectionSuccessMessage());
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        String normalizedName = plugin.getNormalizationUtil().normalizeName(event.getPlayer().getName());
        
        // Hapus waktu mulai sesi
        Long startTime = sessionStartTime.remove(normalizedName);
        
        if (startTime != null) {
            long sessionDuration = System.currentTimeMillis() - startTime;
            
            try {
                // Perbarui playtime di binding (yang ada di cache RAM)
                // Ini aman dari I/O karena pemain yang quit pasti ada di cache
                bindingManager.getBinding(normalizedName).ifPresent(binding -> {
                    binding.addPlaytime(sessionDuration);
                    
                    // Perbarui trust level berdasarkan playtime
                    if (binding.getTrust() == Binding.TrustLevel.LOW && 
                        binding.getTotalPlaytime() > configManager.getLowTrustPlaytimeMillis()) {
                        
                        binding.setTrust(Binding.TrustLevel.MEDIUM);
                        plugin.getSLF4JLogger().info("Updated trust level for {} to MEDIUM.", normalizedName);
                    }
                });
            } catch (IOException e) {
                // Seharusnya tidak terjadi (karena ada di cache), tapi tetap tangani
                plugin.getSLF4JLogger().error("Failed to retrieve cached binding for {} on quit.", normalizedName, e);
            }
        }
        
        // Simpan binding (yang sudah di-update) ke disk dan hapus dari cache RAM
        bindingManager.unloadBinding(normalizedName);
    }
}
