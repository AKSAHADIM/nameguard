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
 * V4:
 * - Adds optional Geo-IP signals (from external resolver such as ipwho.is) to improve similarity decisions:
 *   countryCode, region, city, asn, org, isp.
 * - Backward compatible loading: older V3 entries without these fields remain valid.
 */
public final class Fingerprint implements Serializable {

    private static final long serialVersionUID = 4L; // Version 4 (adds geo fields)

    private final long createdAt;

    // --- Strong Identity Signals ---
    @Nullable
    private final String xuid; // Strong identity for Bedrock
    @Nullable
    private final String javaUuid; // Strong identity for Java (meaningful in online-mode; stored for context)

    // --- Heuristic Network Signals (local, privacy-preserving hashes) ---
    @NotNull
    private final String ipVersion; // v4 / v6
    @Nullable
    private final String hashedPrefix; // HMAC-SHA256 of subnet prefix (/24 IPv4, /48 IPv6)
    @Nullable
    private final String hashedPtr; // HMAC-SHA256 of PTR hostname
    @Nullable
    private final String hashedPseudoAsn; // HMAC-SHA256 of pseudo-ASN (local /16 derived)

    // --- Client Signals ---
    @Nullable
    private final String clientBrand; // e.g., "vanilla", "geyser", "java"
    @Nullable
    private final String protocolVersion; // protocol string if available
    @NotNull
    private final AccountType edition; // JAVA / BEDROCK
    @Nullable
    private final String deviceOs; // e.g., "Android", "Windows" (mostly for Bedrock)

    // --- Geo-IP Signals (Optional, from external resolver; stored as plaintext strings) ---
    // All are optional and may be null if resolver disabled/unavailable.
    @Nullable
    private final String countryCode; // e.g., "SG", "ID"
    @Nullable
    private final String region; // e.g., "Southeast" or province/state name
    @Nullable
    private final String city; // e.g., "Singapore", "Jakarta"
    @Nullable
    private final String asn; // e.g., "14061"
    @Nullable
    private final String org; // e.g., "Digitalocean, LLC"
    @Nullable
    private final String isp; // e.g., "Digitalocean, LLC"

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

        this.countryCode = builder.countryCode;
        this.region = builder.region;
        this.city = builder.city;
        this.asn = builder.asn;
        this.org = builder.org;
        this.isp = builder.isp;
    }

    // Constructor for deserialization from map
    private Fingerprint(long createdAt,
                        @Nullable String xuid,
                        @Nullable String javaUuid,
                        @NotNull String ipVersion,
                        @Nullable String hashedPrefix,
                        @Nullable String hashedPtr,
                        @Nullable String hashedPseudoAsn,
                        @Nullable String clientBrand,
                        @Nullable String protocolVersion,
                        @NotNull AccountType edition,
                        @Nullable String deviceOs,
                        @Nullable String countryCode,
                        @Nullable String region,
                        @Nullable String city,
                        @Nullable String asn,
                        @Nullable String org,
                        @Nullable String isp) {
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

        this.countryCode = countryCode;
        this.region = region;
        this.city = city;
        this.asn = asn;
        this.org = org;
        this.isp = isp;
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

    @Nullable
    public String getCountryCode() {
        return countryCode;
    }

    @Nullable
    public String getRegion() {
        return region;
    }

    @Nullable
    public String getCity() {
        return city;
    }

    @Nullable
    public String getAsn() {
        return asn;
    }

    @Nullable
    public String getOrg() {
        return org;
    }

    @Nullable
    public String getIsp() {
        return isp;
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

        private String countryCode;
        private String region;
        private String city;
        private String asn;
        private String org;
        private String isp;

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

        public Builder countryCode(@Nullable String countryCode) {
            this.countryCode = countryCode;
            return this;
        }

        public Builder region(@Nullable String region) {
            this.region = region;
            return this;
        }

        public Builder city(@Nullable String city) {
            this.city = city;
            return this;
        }

        public Builder asn(@Nullable String asn) {
            this.asn = asn;
            return this;
        }

        public Builder org(@Nullable String org) {
            this.org = org;
            return this;
        }

        public Builder isp(@Nullable String isp) {
            this.isp = isp;
            return this;
        }

        public Fingerprint build() {
            return new Fingerprint(this);
        }
    }

    /**
     * Helper method to manually construct a Fingerprint from a Map (like a LinkedHashMap from SnakeYAML).
     * This handles V2, V3, and V4 format loading.
     * If map format is unknown/legacy, return null and let the binding manager trigger fresh registration on login.
     */
    @NotNull
    @SuppressWarnings("unchecked")
    public static Fingerprint fromMap(@NotNull Map<String, Object> map) {
        long createdAt = ((Number) map.getOrDefault("createdAt", 0L)).longValue();

        // Handle V1/V2 migration (old hash/GeoIP structure)
        if (map.containsKey("value") || map.containsKey("asn") || map.containsKey("country")) {
            // Signal error for old/unsupported map, let caller decide to skip/add new.
            throw new IllegalArgumentException("Legacy fingerprint format detected, skipping/rebinding required.");
        }

        // V3/V4 fields
        String xuid = (String) map.get("xuid");
        String javaUuid = (String) map.get("javaUuid");
        String ipVersion = (String) map.getOrDefault("ipVersion", "v4"); // default v4 if missing

        // Network signals (HMAC hashes)
        String hashedPrefix = (String) map.get("hashedPrefix");
        String hashedPtr = (String) map.get("hashedPtr");
        String hashedPseudoAsn = (String) map.get("hashedPseudoAsn");

        // Client signals
        String clientBrand = (String) map.get("clientBrand");
        String protocolVersion = (String) map.get("protocolVersion");
        AccountType edition = AccountType.valueOf((String) map.getOrDefault("edition", "JAVA"));
        String deviceOs = (String) map.get("deviceOs");

        // V4 Geo signals (optional, may be absent on legacy entries)
        String countryCode = (String) map.get("countryCode");
        String region = (String) map.get("region");
        String city = (String) map.get("city");
        String asn = (String) map.get("asn");
        String org = (String) map.get("org");
        String isp = (String) map.get("isp");

        return new Fingerprint(createdAt, xuid, javaUuid, ipVersion, hashedPrefix, hashedPtr, hashedPseudoAsn,
                clientBrand, protocolVersion, edition, deviceOs,
                countryCode, region, city, asn, org, isp);
    }

    // We override equals and hashCode to ensure that two fingerprints are only
    // considered "equal" if all their signals match perfectly (used by List.contains).

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fingerprint that = (Fingerprint) o;
        // Compare all V4 fields
        return edition == that.edition &&
                Objects.equals(xuid, that.xuid) &&
                Objects.equals(javaUuid, that.javaUuid) &&
                Objects.equals(ipVersion, that.ipVersion) &&
                Objects.equals(hashedPrefix, that.hashedPrefix) &&
                Objects.equals(hashedPtr, that.hashedPtr) &&
                Objects.equals(hashedPseudoAsn, that.hashedPseudoAsn) &&
                Objects.equals(clientBrand, that.clientBrand) &&
                Objects.equals(protocolVersion, that.protocolVersion) &&
                Objects.equals(deviceOs, that.deviceOs) &&
                Objects.equals(countryCode, that.countryCode) &&
                Objects.equals(region, that.region) &&
                Objects.equals(city, that.city) &&
                Objects.equals(asn, that.asn) &&
                Objects.equals(org, that.org) &&
                Objects.equals(isp, that.isp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(xuid, javaUuid, ipVersion, hashedPrefix, hashedPtr, hashedPseudoAsn,
                clientBrand, protocolVersion, edition, deviceOs,
                countryCode, region, city, asn, org, isp);
    }
}
