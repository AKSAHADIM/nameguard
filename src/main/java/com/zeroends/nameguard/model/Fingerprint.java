package com.zeroends.nameguard.model;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a multi-factor digital "fingerprint" of a player's connection properties.
 * This class is immutable.
 *
 * This version stores individual signals, including locally derived heuristic network signals (V3).
 */
public final class Fingerprint implements Serializable {

    private static final long serialVersionUID = 3L; // Version 3

    private final long createdAt;

    // --- Sinyal Identitas Kuat ---
    @Nullable
    private final String xuid; // Identitas kuat Bedrock
    @Nullable
    private final String javaUuid; // Identitas kuat Java (jika online mode, tapi diabaikan di offline)

    // --- Sinyal Jaringan Heuristik (V3) ---
    @NotNull
    private final String ipVersion; // v4 / v6
    @Nullable
    private final String hashedPrefix; // HMAC-SHA256 hash dari subnet prefix (/24 atau /48)
    @Nullable
    private final String hashedPtr; // HMAC-SHA256 hash dari PTR hostname
    @Nullable
    private final String hashedPseudoAsn; // HMAC-SHA256 hash dari Pseudo-ASN (block IP awal)

    // --- Sinyal Klien (Client) ---
    @Nullable
    private final String clientBrand; // Merek klien (z.B. "vanilla", "geyser")
    @Nullable
    private final String protocolVersion; // Versi protokol
    @NotNull
    private final AccountType edition; // JAVA / BEDROCK
    @Nullable
    private final String deviceOs; // OS Perangkat (z.B. "Android", "Windows")


    // Builder pattern constructor
    private Fingerprint(Builder builder) {
        this.createdAt = System.currentTimeMillis();
        this.xuid = builder.xuid;
        this.javaUuid = builder.javaUuid;
        
        this.ipVersion = Objects.requireNonNull(builder.ipVersion, "IP Version cannot be null");
        this.hashedPrefix = builder.hashedPrefix;
        this.hashedPtr = builder.hashedPtr;
        this.hashedPseudoAsn = builder.hashedPseudoAsn;
        
        this.clientBrand = builder.clientBrand;
        this.protocolVersion = builder.protocolVersion;
        this.edition = Objects.requireNonNull(builder.edition, "Edition cannot be null");
        this.deviceOs = builder.deviceOs;
    }

    // Constructor for deserialization from map
    private Fingerprint(long createdAt, @Nullable String xuid, @Nullable String javaUuid,
                        @NotNull String ipVersion, @Nullable String hashedPrefix, @Nullable String hashedPtr, @Nullable String hashedPseudoAsn,
                        @Nullable String clientBrand, @Nullable String protocolVersion,
                        @NotNull AccountType edition, @Nullable String deviceOs) {
        this.createdAt = createdAt;
        this.xuid = xuid;
        this.javaUuid = javaUuid;
        this.ipVersion = ipVersion;
        this.hashedPrefix = hashedPrefix;
        this.hashedPtr = hashedPtr;
        this.hashedPseudoAsn = hashedPseudoAsn;
        this.clientBrand = clientBrand;
        this.protocolVersion = protocolVersion;
        this.edition = edition;
        this.deviceOs = deviceOs;
    }

    // --- Getters ---

    public long getCreatedAt() {
        return createdAt;
    }

    @Nullable
    public String getXuid() {
        return xuid;
    }

    @Nullable
    public String getJavaUuid() {
        return javaUuid;
    }

    @NotNull
    public String getIpVersion() {
        return ipVersion;
    }

    @Nullable
    public String getHashedPrefix() {
        return hashedPrefix;
    }

    @Nullable
    public String getHashedPtr() {
        return hashedPtr;
    }

    @Nullable
    public String getHashedPseudoAsn() {
        return hashedPseudoAsn;
    }

    @Nullable
    public String getClientBrand() {
        return clientBrand;
    }

    @Nullable
    public String getProtocolVersion() {
        return protocolVersion;
    }

    @NotNull
    public AccountType getEdition() {
        return edition;
    }

    @Nullable
    public String getDeviceOs() {
        return deviceOs;
    }
    
    // --- Builder Class ---

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String xuid;
        private String javaUuid;
        private String ipVersion;
        private String hashedPrefix;
        private String hashedPtr;
        private String hashedPseudoAsn;
        private String clientBrand;
        private String protocolVersion;
        private AccountType edition;
        private String deviceOs;

        public Builder edition(@NotNull AccountType edition) {
            this.edition = edition;
            return this;
        }

        public Builder xuid(@Nullable String xuid) {
            this.xuid = xuid;
            return this;
        }

        public Builder javaUuid(@Nullable String javaUuid) {
            this.javaUuid = javaUuid;
            return this;
        }

        public Builder ipVersion(@NotNull String ipVersion) {
            this.ipVersion = ipVersion;
            return this;
        }

        public Builder hashedPrefix(@Nullable String hashedPrefix) {
            this.hashedPrefix = hashedPrefix;
            return this;
        }

        public Builder hashedPtr(@Nullable String hashedPtr) {
            this.hashedPtr = hashedPtr;
            return this;
        }

        public Builder hashedPseudoAsn(@Nullable String hashedPseudoAsn) {
            this.hashedPseudoAsn = hashedPseudoAsn;
            return this;
        }

        public Builder clientBrand(@Nullable String clientBrand) {
            this.clientBrand = clientBrand;
            return this;
        }

        public Builder protocolVersion(@Nullable String protocolVersion) {
            this.protocolVersion = protocolVersion;
            return this;
        }

        public Builder deviceOs(@Nullable String deviceOs) {
            this.deviceOs = deviceOs;
            return this;
        }

        public Fingerprint build() {
            return new Fingerprint(this);
        }
    }


    /**
     * Helper method to manually construct a Fingerprint from a Map (like a LinkedHashMap from SnakeYAML).
     * This handles V2 and V3 format loading.
     * @param map The map of values from YAML.
     * @return A new Fingerprint object.
     */
    @NotNull
    @SuppressWarnings("unchecked")
    public static Fingerprint fromMap(@NotNull Map<String, Object> map) {
        long createdAt = ((Number) map.getOrDefault("createdAt", 0L)).longValue();
        
        // Handle V1/V2 migration (old hash/GeoIP structure)
        if (map.containsKey("value") || map.containsKey("asn") || map.containsKey("country")) {
             // Treat old format as invalid/migrated. Force re-registration.
             return new Fingerprint(
                createdAt, null, null, "v4", null, null, null,
                "migrated_v2", null, AccountType.JAVA, null
             );
        }

        // Load V3 fields
        String xuid = (String) map.get("xuid");
        String javaUuid = (String) map.get("javaUuid");
        String ipVersion = (String) map.getOrDefault("ipVersion", "v4"); // Default to v4 if missing
        
        // V3 Network Signals (HMAC hashes)
        String hashedPrefix = (String) map.get("hashedPrefix");
        String hashedPtr = (String) map.get("hashedPtr");
        String hashedPseudoAsn = (String) map.get("hashedPseudoAsn");
        
        // Client Signals
        String clientBrand = (String) map.get("clientBrand");
        String protocolVersion = (String) map.get("protocolVersion");
        AccountType edition = AccountType.valueOf((String) map.getOrDefault("edition", "JAVA"));
        String deviceOs = (String) map.get("deviceOs");

        return new Fingerprint(createdAt, xuid, javaUuid, ipVersion, hashedPrefix, hashedPtr, hashedPseudoAsn,
                               clientBrand, protocolVersion, edition, deviceOs);
    }
    
    // We override equals and hashCode to ensure that two fingerprints are only
    // considered "equal" if all their signals match perfectly (used by List.contains).
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fingerprint that = (Fingerprint) o;
        // Compare all V3 fields
        return edition == that.edition &&
               Objects.equals(xuid, that.xuid) &&
               Objects.equals(javaUuid, that.javaUuid) &&
               Objects.equals(ipVersion, that.ipVersion) &&
               Objects.equals(hashedPrefix, that.hashedPrefix) &&
               Objects.equals(hashedPtr, that.hashedPtr) &&
               Objects.equals(hashedPseudoAsn, that.hashedPseudoAsn) &&
               Objects.equals(clientBrand, that.clientBrand) &&
               Objects.equals(protocolVersion, that.protocolVersion) &&
               Objects.equals(deviceOs, that.deviceOs);
    }

    @Override
    public int hashCode() {
        return Objects.hash(xuid, javaUuid, ipVersion, hashedPrefix, hashedPtr, hashedPseudoAsn,
                            clientBrand, protocolVersion, edition, deviceOs);
    }
}
