package com.zeroends.nameguard;

import com.zeroends.nameguard.command.NameGuardCommand;
import com.zeroends.nameguard.listener.PlayerConnectionListener;
import com.zeroends.nameguard.manager.BindingManager;
import com.zeroends.nameguard.manager.ConfigManager;
import com.zeroends.nameguard.manager.FingerprintManager;
import com.zeroends.nameguard.storage.IStorage;
import com.zeroends.nameguard.storage.YamlStorage;
import com.zeroends.nameguard.util.NormalizationUtil;
import com.zeroends.nameguard.util.IpHeuristicUtil;
import org.bukkit.plugin.java.JavaPlugin;
import org.geysermc.floodgate.api.FloodgateApi;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class NameGuard extends JavaPlugin {

    private ConfigManager configManager;
    private IStorage storage;
    private BindingManager bindingManager;
    private FingerprintManager fingerprintManager;
    private NormalizationUtil normalizationUtil;
    private IpHeuristicUtil ipHeuristicUtil;
    private FloodgateApi floodgateApi;

    // Concurrency lock map for player logins
    private final ConcurrentHashMap<String, Object> loginLocks = new ConcurrentHashMap<>();

    @Override
    public void onEnable() {
        // 1. Setup Config
        this.configManager = new ConfigManager(this);
        configManager.loadConfig();

        // 2. Setup Utilities
        this.normalizationUtil = new NormalizationUtil();
        this.ipHeuristicUtil = new IpHeuristicUtil(configManager.getHmacSalt());
        
        // 3. Setup Storage (V3 Hybrid Model)
        // We no longer point to "identities.yml". We point to the root data folder.
        // YamlStorage will handle the "/data" subdirectory internally.
        try {
            this.storage = new YamlStorage(getDataFolder().toPath(), getSLF4JLogger());
            this.storage.init(); // This will create the '/data' directory
        } catch (IOException e) {
            getSLF4JLogger().error("Failed to initialize YAML storage directory. Disabling plugin.", e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // 4. Setup Managers
        this.fingerprintManager = new FingerprintManager(this, ipHeuristicUtil);
        this.bindingManager = new BindingManager(this, storage, normalizationUtil, fingerprintManager);
        
        // REMOVED in Hybrid Model: bindingManager.loadAllBindings();
        // Bindings will be loaded on demand when players join.
        
        // 5. Setup Hooks (Floodgate)
        if (getServer().getPluginManager().isPluginEnabled("Floodgate")) {
            try {
                this.floodgateApi = FloodgateApi.getInstance();
                getSLF4JLogger().info("Successfully hooked into Floodgate API.");
            } catch (Exception e) {
                getSLF4JLogger().warn("Failed to hook into Floodgate API, Bedrock support will be limited.", e);
                this.floodgateApi = null;
            }
        } else {
            getSLF4JLogger().info("Floodgate not found. Bedrock (Geyser) players will be treated as standard Java offline players.");
            this.floodgateApi = null;
        }

        // 6. Register Listeners and Commands
        getServer().getPluginManager().registerEvents(new PlayerConnectionListener(this), this);
        Objects.requireNonNull(getCommand("nameguard")).setExecutor(new NameGuardCommand(this));

        getSLF4JLogger().info("NameGuard (Hybrid Storage) has been enabled successfully.");
    }

    @Override
    public void onDisable() {
        if (bindingManager != null) {
            // Save any remaining "dirty" bindings (players still online)
            bindingManager.saveCacheToDisk();
        }
        loginLocks.clear();
        
        getSLF4JLogger().info("NameGuard has been disabled.");
    }

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public BindingManager getBindingManager() {
        return bindingManager;
    }

    public FingerprintManager getFingerprintManager() {
        return fingerprintManager;
    }

    public NormalizationUtil getNormalizationUtil() {
        return normalizationUtil;
    }
    
    public IpHeuristicUtil getIpHeuristicUtil() {
        return ipHeuristicUtil;
    }

    public Optional<FloodgateApi> getFloodgateApi() {
        return Optional.ofNullable(floodgateApi);
    }

    public ConcurrentHashMap<String, Object> getLoginLocks() {
        return loginLocks;
    }
}
