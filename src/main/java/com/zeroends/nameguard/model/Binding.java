package com.zeroends.nameguard.model;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Represents the identity "binding" for a specific player name.
 * This class links a canonical name to its associated identity proofs.
 */
public class Binding implements Serializable {

    private static final long serialVersionUID = 3L; // Version 3

    // The canonical (normalized) player name
    @NotNull
    private final String normalizedName;

    // The preferred casing (display name)
    @NotNull
    private String preferredName;

    @NotNull
    private AccountType accountType;

    // A rolling list of known, valid fingerprints for this user.
    @NotNull
    private final List<Fingerprint> fingerprints;

    private long firstSeen;
    private long lastSeen;
    private long totalPlaytime; // in milliseconds

    // Trust level, determines vulnerability to takeover
    @NotNull
    private TrustLevel trust;

    // Constructor for new bindings
    public Binding(@NotNull String normalizedName, @NotNull String preferredName, @NotNull AccountType accountType, @NotNull Fingerprint initialFingerprint) {
        this.normalizedName = Objects.requireNonNull(normalizedName, "Normalized name cannot be null");
        this.preferredName = Objects.requireNonNull(preferredName, "Preferred name cannot be null");
        this.accountType = Objects.requireNonNull(accountType, "Account type cannot be null");
        
        this.fingerprints = new CopyOnWriteArrayList<>();
        this.fingerprints.add(Objects.requireNonNull(initialFingerprint, "Initial fingerprint cannot be null"));
        
        long now = System.currentTimeMillis();
        this.firstSeen = now;
        this.lastSeen = now;
        this.totalPlaytime = 0;
        this.trust = TrustLevel.LOW; // All new bindings start with low trust
    }
    
    // Private constructor for deserialization from map
    private Binding(@NotNull String normalizedName, @NotNull String preferredName, @NotNull AccountType accountType,
                    @NotNull List<Fingerprint> fingerprints, long firstSeen, long lastSeen,
                    long totalPlaytime, @NotNull TrustLevel trust) {
        this.normalizedName = normalizedName;
        this.preferredName = preferredName;
        this.accountType = accountType;
        this.fingerprints = new CopyOnWriteArrayList<>(fingerprints);
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        this.totalPlaytime = totalPlaytime;
        this.trust = trust;
    }

    @NotNull
    public String getNormalizedName() {
        return normalizedName;
    }

    @NotNull
    public String getPreferredName() {
        return preferredName;
    }

    public void setPreferredName(@NotNull String preferredName) {
        this.preferredName = Objects.requireNonNull(preferredName);
    }

    @NotNull
    public AccountType getAccountType() {
        return accountType;
    }

    public void setAccountType(@NotNull AccountType accountType) {
        this.accountType = Objects.requireNonNull(accountType);
    }

    @NotNull
    public List<Fingerprint> getFingerprints() {
        return fingerprints;
    }

    /**
     * Adds a new fingerprint, automatically managing the rolling list limit.
     * @param fp The new fingerprint to add.
     * @param limit The maximum number of fingerprints to keep.
     */
    public void addFingerprint(@NotNull Fingerprint fp, int limit) {
        Objects.requireNonNull(fp);
        if (!fingerprints.contains(fp)) {
            fingerprints.add(fp);
            // Evict oldest if limit is exceeded
            while (limit > 0 && fingerprints.size() > limit) {
                // Find the oldest fingerprint to remove
                fingerprints.stream()
                        .min((fp1, fp2) -> Long.compare(fp1.getCreatedAt(), fp2.getCreatedAt()))
                        .ifPresent(fingerprints::remove);
            }
        }
    }

    /**
     * Removes fingerprints that are older than the specified retention period.
     * @param purgeMillis The retention period in milliseconds.
     * @param minToKeep The minimum number of fingerprints to keep, regardless of age.
     */
    public void purgeOldFingerprints(long purgeMillis, int minToKeep) {
        if (purgeMillis <= 0) {
            return;
        }

        long purgeBefore = System.currentTimeMillis() - purgeMillis;
        fingerprints.removeIf(fp -> fingerprints.size() > minToKeep && fp.getCreatedAt() < purgeBefore);
    }

    public long getFirstSeen() {
        return firstSeen;
    }

    public long getLastSeen() {
        return lastSeen;
    }

    public void updateLastSeen() {
        this.lastSeen = System.currentTimeMillis();
    }

    public long getTotalPlaytime() {
        return totalPlaytime;
    }

    public void addPlaytime(long sessionDuration) {
        if (sessionDuration > 0) {
            this.totalPlaytime += sessionDuration;
        }
    }

    @NotNull
    public TrustLevel getTrust() {
        return trust;
    }

    public void setTrust(@NotNull TrustLevel trust) {
        this.trust = Objects.requireNonNull(trust);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Binding binding = (Binding) o;
        return normalizedName.equals(binding.normalizedName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(normalizedName);
    }

    /**
     * Represents the trust level of a binding, used for takeover policies.
     */
    public enum TrustLevel {
        LOW,    // New players, vulnerable to takeover
        MEDIUM, // Established players
        HIGH,   // Verified or admin-locked players
        LOCKED  // Manually locked by an admin, cannot be taken over
    }

    /**
     * Helper method to manually construct a Binding from a Map (like a LinkedHashMap from SnakeYAML).
     * @param normalizedName The key (normalized name) of the binding.
     * @param map The map of values from YAML.
     * @return A new Binding object.
     * @throws ClassCastException if the map is malformed.
     */
    @NotNull
    @SuppressWarnings("unchecked")
    public static Binding fromMap(@NotNull String normalizedName, @NotNull Map<String, Object> map) {
        String preferredName = (String) map.get("preferredName");
        AccountType accountType = AccountType.valueOf((String) map.get("accountType"));
        TrustLevel trust = TrustLevel.valueOf((String) map.getOrDefault("trust", "LOW"));
        
        long firstSeen = ((Number) map.getOrDefault("firstSeen", 0L)).longValue();
        long lastSeen = ((Number) map.getOrDefault("lastSeen", 0L)).longValue();
        long totalPlaytime = ((Number) map.getOrDefault("totalPlaytime", 0L)).longValue();

        List<Fingerprint> fingerprints = new ArrayList<>();
        
        List<Map<String, Object>> fpData = (List<Map<String, Object>>) map.get("fingerprints");
        if (fpData != null) {
            for (Map<String, Object> fpMap : fpData) {
                try {
                    // Use Fingerprint.fromMap to parse V3 structure
                    fingerprints.add(Fingerprint.fromMap(fpMap));
                } catch (Exception e) {
                    // Log error or ignore malformed fingerprint
                }
            }
        }

        return new Binding(normalizedName, preferredName, accountType, fingerprints, firstSeen, lastSeen, totalPlaytime, trust);
    }
}
