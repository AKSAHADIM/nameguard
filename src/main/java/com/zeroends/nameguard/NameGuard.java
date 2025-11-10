package com.zeroends.nameguard;

import com.zeroends.nameguard.command.NameGuardCommand;
import com.zeroends.nameguard.listener.PlayerConnectionListener;
import com.zeroends.nameguard.manager.BindingManager;
import com.zeroends.nameguard.manager.ConfigManager;
import com.zeroends.nameguard.manager.FingerprintManager;
import com.zeroends.nameguard.storage.IStorage;
import com.zeroends.nameguard.storage.YamlStorage;
import com.zeroends.nameguard.util.GeoIpUtil;
import com.zeroends.nameguard.util.NormalizationUtil;
import com.zeroends.nameguard.util.IpHeuristicUtil;
import org.bukkit.plugin.java.JavaPlugin;
import org.geysermc.floodgate.api.FloodgateApi;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Main plugin entry point.
 *
 * V4 Changes:
 *  - Integrates GeoIpUtil (ipwho.is) for optional geo signals (country, city/region, ASN, org, isp).
 *  - Passes GeoIpUtil into FingerprintManager constructor.
 */
public final class NameGuard extends JavaPlugin {

    private ConfigManager configManager;
    private IStorage storage;
    private BindingManager bindingManager;
    private FingerprintManager fingerprintManager;
    private NormalizationUtil normalizationUtil;
    private IpHeuristicUtil ipHeuristicUtil;
    private GeoIpUtil geoIpUtil;
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
        this.geoIpUtil = GeoIpUtil.create(getSLF4JLogger(), configManager);

        // 3. Setup Storage (Hybrid Model: file-per-player)
        try {
            this.storage = new YamlStorage(getDataFolder().toPath(), getSLF4JLogger());
            this.storage.init(); // create '/data' directory
        } catch (IOException e) {
            getSLF4JLogger().error("Failed to initialize YAML storage directory. Disabling plugin.", e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        // 4. Setup Managers
        this.fingerprintManager = new FingerprintManager(this, ipHeuristicUtil, geoIpUtil);
        this.bindingManager = new BindingManager(this, storage, normalizationUtil, fingerprintManager);

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

        getSLF4JLogger().info("NameGuard v4 (Geo + Strict Gating) has been enabled successfully.");
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

    public GeoIpUtil getGeoIpUtil() {
        return geoIpUtil;
    }

    public Optional<FloodgateApi> getFloodgateApi() {
        return Optional.ofNullable(floodgateApi);
    }

    public ConcurrentHashMap<String, Object> getLoginLocks() {
        return loginLocks;
    }
}
