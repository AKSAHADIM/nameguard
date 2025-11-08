package com.zeroends.nameguard.model;

import net.kyori.adventure.text.Component;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * Represents the outcome of a login verification check.
 * This is an immutable sealed class.
 */
public sealed interface LoginResult {

    /**
     * Represents a successful login.
     *
     * @param binding        The binding associated with the player.
     * @param isNewBinding   True if this binding was just created for this session.
     * @param isSoftMatch    True if the login was allowed based on a "soft match" (e.g., similar fingerprint).
     */
    record Allowed(
            @NotNull Binding binding,
            boolean isNewBinding,
            boolean isSoftMatch
    ) implements LoginResult {
        public Allowed {
            Objects.requireNonNull(binding, "Binding cannot be null");
        }
    }

    /**
     * Represents a denied login.
     *
     * @param reason     The internal reason code for the denial.
     * @param kickMessage The user-facing kick message (pre-formatted).
     */
    record Denied(
            @NotNull Reason reason,
            @Nullable Component kickMessage
    ) implements LoginResult {
        public Denied {
            Objects.requireNonNull(reason, "Reason cannot be null");
        }
    }

    /**
     * Internal reason codes for why a login might be denied.
     */
    enum Reason {
        /**
         * The fingerprint is drastically different from the registered ones.
         * (Kasus 3, 7)
         */
        HARD_MISMATCH,

        /**
         * A player from a different edition (Java/Bedrock) tried to use the name.
         * (Kasus 4, 5)
         */
        CROSS_EDITION_LOCK,

        /**
         * The name used is a "confusable" or normalized version of a protected name.
         * (Kasus 10)
         */
        CONFUSABLE_NAME_SPOOF,

        /**
         * The player/IP has hit the rate limit for failed login attempts.
         * (Kasus 9)
         */
        RATE_LIMITED,

        /**
         * An internal plugin error occurred during verification.
         */
        INTERNAL_ERROR,

        /**
         * Login was denied by an admin or other mechanism.
         */
        UNKNOWN
    }
}
