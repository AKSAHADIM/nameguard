package com.zeroends.nameguard.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale; // FIX: Import Locale
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Utility class to derive local, non-GeoIP based heuristic signals from an InetAddress.
 * Used for the V3 multi-signal fingerprinting system.
 */
public class IpHeuristicUtil {

    private final String salt;

    public IpHeuristicUtil(@NotNull String salt) {
        this.salt = salt;
    }

    /**
     * Generates a secure HMAC-SHA256 hash of the input data using the configured salt.
     * @param data The input string data (e.g., subnet prefix, PTR domain).
     * @return The hex-encoded HMAC hash.
     */
    @NotNull
    public String hmacSha256(@NotNull String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(salt.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            // Should not happen with standard Java JREs
            throw new RuntimeException("HMAC-SHA256 error: " + e.getMessage());
        }
    }

    /**
     * Derives a subnet prefix for fingerprinting (Class C for IPv4, /48 for IPv6).
     * @param address The IP address.
     * @return The subnet prefix string (e.g., "103.160.182.0/24").
     */
    @Nullable
    public String getSubnetPrefix(@NotNull InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) { // IPv4
            // /24 prefix
            return (bytes[0] & 0xFF) + "." + (bytes[1] & 0xFF) + "." + (bytes[2] & 0xFF) + ".0/24";
        } else if (bytes.length == 16) { // IPv6
            // /48 prefix
            return String.format("%02x%02x:%02x%02x:%02x%02x::/48",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        }
        return null;
    }

    /**
     * Derives a Pseudo-ASN by hashing the first two bytes of the IP address.
     * This approximates the Autonomous System Number (ASN) provider without GeoIP.
     * @param address The IP address.
     * @return Pseudo-ASN string (e.g., "103160") or null.
     */
    @Nullable
    public String getPseudoAsn(@NotNull InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length >= 2) {
            // We use the first two bytes of the IP address, which are usually assigned per network block/region.
            // Format: B1B2 (e.g., 103.160.x.x -> "103160")
            int b1 = bytes[0] & 0xFF;
            int b2 = bytes[1] & 0xFF;
            return String.valueOf(b1 * 256 + b2); // Unique ID for the /16 block
        }
        return null;
    }

    /**
     * Performs a reverse DNS lookup (PTR record) asynchronously.
     * @param address The IP address.
     * @return A CompletableFuture of the PTR hostname, timing out after 1 second.
     */
    @NotNull
    public CompletableFuture<String> getPTR(@NotNull InetAddress address) {
        // FIX: Explicitly specify return type <String> for CompletableFuture
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Performing reverse lookup
                String host = address.getCanonicalHostName();
                // If it resolves to the IP itself, it usually means no PTR record is set
                if (host.equals(address.getHostAddress())) {
                    return null;
                }
                return host.toLowerCase(Locale.ROOT);
            } catch (Exception e) {
                return null; // DNS lookup failed
            }
        }).orTimeout(1, TimeUnit.SECONDS) // Timeout to prevent thread blocking
          .exceptionally(ex -> null); // Return null on timeout or failure
    }

    /**
     * Determines the IP version.
     * @param address The IP address.
     * @return "v4" or "v6".
     */
    @NotNull
    public String getIpVersion(@NotNull InetAddress address) {
        return address.getAddress().length == 4 ? "v4" : "v6";
    }
}
