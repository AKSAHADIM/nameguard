package com.zeroends.nameguard.model;

/**
 * Represents the type of account that first registered a name.
 */
public enum AccountType {
    /**
     * A Java Edition account, likely in offline mode.
     * Identity is verified by Fingerprint (L2).
     */
    JAVA,

    /**
     * A Bedrock Edition account, likely via Geyser/Floodgate.
     * Identity is verified by Fingerprint (L2) or XUID (L3) if available.
     */
    BEDROCK
}
