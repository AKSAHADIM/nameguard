package com.zeroends.nameguard.storage;

import com.zeroends.nameguard.model.Binding;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.Optional;

/**
 * Interface for a storage backend that handles persisting and retrieving Bindings.
 * This (V3 Hybrid) interface is designed for loading individual bindings on demand,
 * rather than loading all bindings into memory at once.
 */
public interface IStorage {

    /**
     * Initializes the storage backend (e.g., creates directories).
     * @throws IOException If initialization fails.
     */
    void init() throws IOException;

    /**
     * Loads a specific Binding from the storage backend based on the normalized name.
     * This is expected to perform I/O (e.g., read a file).
     *
     * @param normalizedName The normalized name of the player.
     * @return An Optional<Binding> containing the binding if found, or empty if not.
     * @throws IOException If a read error occurs.
     */
    Optional<Binding> loadBinding(@NotNull String normalizedName) throws IOException;

    /**
     * Saves a specific Binding to the storage backend.
     * This is expected to perform I/O (e.g., write to a file).
     *
     * @param binding The Binding object to save.
     * @throws IOException If a write error occurs.
     */
    void saveBinding(@NotNull Binding binding) throws IOException;

    /**
     * Removes a specific Binding from the storage backend.
     *
     * @param normalizedName The normalized name of the binding to remove.
     * @throws IOException If a delete error occurs.
     */
    void removeBinding(@NotNull String normalizedName) throws IOException;

    /**
     * Shuts down the storage handler (e.g., closes file handles).
     * (No longer strictly necessary for file-per-player, but good practice).
     */
    void shutdown();
}
