package com.zeroends.nameguard.listener;

import com.zeroends.nameguard.NameGuard;
import com.zeroends.nameguard.manager.BindingManager;
import com.zeroends.nameguard.manager.ConfigManager;
import com.zeroends.nameguard.model.Binding;
import com.zeroends.nameguard.model.LoginResult;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
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
 * Handles player connection events including login verification, session tracking,
 * and binding updates upon disconnect.
 */
public class PlayerConnectionListener implements Listener {

    private final NameGuard plugin;
    private final BindingManager bindingManager;
    private final ConfigManager configManager;
    private final ConcurrentHashMap<String, Object> loginLocks;

    // For session timing and marking new bindings
    private final ConcurrentHashMap<String, Long> sessionStartTime = new ConcurrentHashMap<>();
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
            return;
        }

        String normalizedName = plugin.getNormalizationUtil().normalizeName(event.getName());
        Object lock = loginLocks.computeIfAbsent(normalizedName, k -> new Object());

        synchronized (lock) {
            try {
                LoginResult result = bindingManager.verifyLogin(event);
                handleLoginResult(event, result);
            } catch (Exception e) {
                plugin.getSLF4JLogger().error("Error during login verification for player '{}':", event.getName(), e);
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        configManager.getKickMessage("internalError"));
            } finally {
                loginLocks.remove(normalizedName);
            }
        }
    }

    private void handleLoginResult(AsyncPlayerPreLoginEvent event, LoginResult result) {
        String normalizedName = plugin.getNormalizationUtil().normalizeName(event.getName());
        if (result instanceof LoginResult.Denied deniedResult) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    Objects.requireNonNullElse(deniedResult.kickMessage(), Component.text("Login denied.", NamedTextColor.RED)));
            logLoginDenial(event, deniedResult);
        } else if (result instanceof LoginResult.Allowed allowedResult) {
            sessionStartTime.put(normalizedName, System.currentTimeMillis());
            if (allowedResult.isNewBinding()) {
                newBindings.add(normalizedName);
            }
        }
    }

    private void logLoginDenial(AsyncPlayerPreLoginEvent event, LoginResult.Denied deniedResult) {
        if (configManager.isLogFailedAttempts()) {
            plugin.getSLF4JLogger().warn("Denied login for player '{}': Reason - {} (IP: {})",
                    event.getName(), deniedResult.reason(), event.getAddress().getHostAddress());
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        String normalizedName = plugin.getNormalizationUtil().normalizeName(event.getPlayer().getName());
        if (newBindings.remove(normalizedName)) {
            Component protectionMessage = configManager.getProtectionSuccessMessage();
            if (!protectionMessage.equals(Component.empty())) {
                event.getPlayer().sendMessage(protectionMessage);
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        String normalizedName = plugin.getNormalizationUtil().normalizeName(event.getPlayer().getName());
        Long startTime = sessionStartTime.remove(normalizedName);

        if (startTime != null) {
            long sessionDuration = System.currentTimeMillis() - startTime;
            updatePlaytimeAndTrust(normalizedName, sessionDuration);
        }

        bindingManager.unloadBinding(normalizedName);
    }

    private void updatePlaytimeAndTrust(String normalizedName, long sessionDuration) {
        if (sessionDuration <= 0) {
            return;
        }

        try {
            bindingManager.getBinding(normalizedName).ifPresent(binding -> {
                binding.addPlaytime(sessionDuration);
                updateTrustLevelIfNecessary(binding);
                bindingManager.saveBinding(binding);
            });
        } catch (IOException e) {
            plugin.getSLF4JLogger().error("Failed to update binding for player '{}'.", normalizedName, e);
        }
    }

    private void updateTrustLevelIfNecessary(Binding binding) {
        if (binding.getTrust() == Binding.TrustLevel.LOW &&
                binding.getTotalPlaytime() > configManager.getLowTrustPlaytimeMillis()) {
            binding.setTrust(Binding.TrustLevel.MEDIUM);
            plugin.getSLF4JLogger().info("Updated trust level for player '{}' to MEDIUM.", binding.getNormalizedName());
        }
    }
}
