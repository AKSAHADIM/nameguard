package com.zeroends.nameguard.storage;

import com.zeroends.nameguard.model.Binding;
import com.zeroends.nameguard.model.Fingerprint;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Implements IStorage using a file-per-player YAML system (V3 Hybrid Model).
 * Each binding is stored in 'plugins/NameGuard/data/[normalizedName].yml'.
 */
public class YamlStorage implements IStorage {

    private final Path dataDirectory;
    private final Logger logger;

    public YamlStorage(@NotNull Path pluginDataFolder, @NotNull Logger logger) {
        this.dataDirectory = pluginDataFolder.resolve("data");
        this.logger = logger;
    }

    @Override
    public void init() throws IOException {
        // Create the 'data' directory if it doesn't exist
        Files.createDirectories(dataDirectory);
    }

    /**
     * Loads a binding by reading its specific .yml file from the data directory.
     */
    @Override
    public Optional<Binding> loadBinding(@NotNull String normalizedName) throws IOException {
        File playerFile = getPlayerFile(normalizedName);
        if (!playerFile.exists()) {
            return Optional.empty();
        }

        YamlConfiguration yaml = YamlConfiguration.loadConfiguration(playerFile);
        
        try {
            // The root of the YAML file *is* the binding map
            Binding binding = Binding.fromMap(normalizedName, yaml.getValues(false));
            return Optional.of(binding);
        } catch (Exception e) {
            logger.error("Failed to parse binding data for {}. File might be corrupt.", normalizedName, e);
            // Rename corrupt file to prevent issues
            File corruptFile = new File(playerFile.getPath() + ".corrupt");
            playerFile.renameTo(corruptFile);
            return Optional.empty();
        }
    }

    /**
     * Saves a binding by writing its data to its specific .yml file.
     * This will overwrite any existing file.
     */
    @Override
    public void saveBinding(@NotNull Binding binding) throws IOException {
        YamlConfiguration yaml = new YamlConfiguration();
        
        // --- Manual Serialization (to match Binding.fromMap) ---
        
        yaml.set("preferredName", binding.getPreferredName());
        yaml.set("accountType", binding.getAccountType().name());
        yaml.set("trust", binding.getTrust().name());
        yaml.set("firstSeen", binding.getFirstSeen());
        yaml.set("lastSeen", binding.getLastSeen());
        yaml.set("totalPlaytime", binding.getTotalPlaytime());

        // Serialize fingerprints
        List<Map<String, Object>> fpMapList = new ArrayList<>();
        for (Fingerprint fp : binding.getFingerprints()) {
            // Manual serialization (to match Fingerprint.fromMap)
            Map<String, Object> fpMap = new HashMap<>();
            fpMap.put("createdAt", fp.getCreatedAt());
            fpMap.put("xuid", fp.getXuid());
            fpMap.put("javaUuid", fp.getJavaUuid());
            fpMap.put("ipVersion", fp.getIpVersion());
            fpMap.put("hashedPrefix", fp.getHashedPrefix());
            fpMap.put("hashedPtr", fp.getHashedPtr());
            fpMap.put("hashedPseudoAsn", fp.getHashedPseudoAsn());
            fpMap.put("clientBrand", fp.getClientBrand());
            fpMap.put("protocolVersion", fp.getProtocolVersion());
            fpMap.put("edition", fp.getEdition().name());
            fpMap.put("deviceOs", fp.getDeviceOs());
            fpMapList.add(fpMap);
        }
        yaml.set("fingerprints", fpMapList);
        
        // --- End Manual Serialization ---

        File playerFile = getPlayerFile(binding.getNormalizedName());
        yaml.save(playerFile);
    }

    /**
     * Removes a binding by deleting its .yml file.
     */
    @Override
    public void removeBinding(@NotNull String normalizedName) throws IOException {
        File playerFile = getPlayerFile(normalizedName);
        if (playerFile.exists()) {
            Files.delete(playerFile.toPath());
        }
    }

    @Override
    public void shutdown() {
        // No persistent file handles, so nothing to shut down.
    }

    /**
     * Helper method to get the file path for a player.
     */
    @NotNull
    private File getPlayerFile(@NotNull String normalizedName) {
        // Sanitize the name to prevent path traversal
        String sanitizedName = normalizedName.replaceAll("[^a-z0-9_]", "");
        return new File(dataDirectory.toFile(), sanitizedName + ".yml");
    }
}
