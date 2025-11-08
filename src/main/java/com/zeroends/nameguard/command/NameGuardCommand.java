package com.zeroends.nameguard.command;

import com.zeroends.nameguard.NameGuard;
import com.zeroends.nameguard.manager.BindingManager;
import com.zeroends.nameguard.manager.ConfigManager;
import com.zeroends.nameguard.manager.FingerprintManager;
import com.zeroends.nameguard.model.Binding;
import com.zeroends.nameguard.model.Fingerprint;
import com.zeroends.nameguard.util.NormalizationUtil;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

public class NameGuardCommand implements CommandExecutor, TabCompleter {

    private final NameGuard plugin;
    private final BindingManager bindingManager;
    private final ConfigManager configManager;
    private final NormalizationUtil normalizationUtil;
    private final FingerprintManager fingerprintManager;

    public NameGuardCommand(NameGuard plugin) {
        this.plugin = plugin;
        this.bindingManager = plugin.getBindingManager();
        this.configManager = plugin.getConfigManager();
        this.normalizationUtil = plugin.getNormalizationUtil();
        this.fingerprintManager = plugin.getFingerprintManager();
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command, @NotNull String label, @NotNull String[] args) {
        if (!sender.hasPermission("nameguard.admin")) {
            sender.sendMessage(Component.text("You do not have permission to use this command.", NamedTextColor.RED));
            return true;
        }

        if (args.length == 0) {
            sendHelp(sender, label);
            return true;
        }

        String subCommand = args[0].toLowerCase();
        switch (subCommand) {
            case "reload" -> handleReload(sender);
            case "unbind" -> handleUnbind(sender, label, args);
            case "bind" -> handleBind(sender, label, args);
            case "check" -> handleCheck(sender, label, args);
            default -> sendHelp(sender, label);
        }
        return true;
    }

    private void handleReload(CommandSender sender) {
        plugin.getSLF4JLogger().info("Reloading NameGuard configuration...");
        configManager.loadConfig();
        // Reload bindings (just saves and clears cache in V3 Hybrid)
        bindingManager.reloadBindings();
        sender.sendMessage(Component.text("NameGuard configuration and bindings cache reloaded.", NamedTextColor.GREEN));
    }

    private void handleUnbind(CommandSender sender, String label, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(Component.text("Usage: /" + label + " unbind <playerName>", NamedTextColor.RED));
            return;
        }
        String playerName = args[1];
        String normalizedName = normalizationUtil.normalizeName(playerName);

        // This method works for both online (cache) and offline (disk) players
        if (bindingManager.removeBinding(normalizedName)) {
            sender.sendMessage(Component.text("Successfully unbound name: " + playerName, NamedTextColor.GREEN));
            plugin.getSLF4JLogger().info("Admin {} unbound name: {}", sender.getName(), playerName);
        } else {
            sender.sendMessage(Component.text("No binding found for name: " + playerName, NamedTextColor.RED));
        }
    }

    private void handleBind(CommandSender sender, String label, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(Component.text("Usage: /" + label + " bind <playerName>", NamedTextColor.RED));
            return;
        }
        String playerName = args[1];
        Player target = Bukkit.getPlayerExact(playerName);

        if (target == null) {
            sender.sendMessage(Component.text("Player " + playerName + " is not online.", NamedTextColor.RED));
            sender.sendMessage(Component.text("This command can only be used on online players to capture their current fingerprint.", NamedTextColor.GRAY));
            return;
        }

        String normalizedName = normalizationUtil.normalizeName(target.getName());
        
        try {
            // getBinding might perform I/O, but player is online, so it should be in cache
            Binding binding = bindingManager.getBinding(normalizedName).orElse(null);

            if (binding == null) {
                sender.sendMessage(Component.text("Error: Player " + playerName + " has no existing binding. This command force-adds a fingerprint to an *existing* binding.", NamedTextColor.RED));
                return;
            }

            // Manually create a fingerprint from the player's current state
            @SuppressWarnings("deprecation")
            var fp = fingerprintManager.createFingerprint(
                    new org.bukkit.event.player.AsyncPlayerPreLoginEvent(
                            target.getName(),
                            target.getAddress().getAddress(),
                            target.getUniqueId())
            );

            binding.addFingerprint(fp, configManager.getRollingFpLimit());
            binding.setTrust(Binding.TrustLevel.LOCKED); // Lock the binding
            bindingManager.saveBinding(binding); // Save changes to cache and disk

            sender.sendMessage(Component.text("Successfully bound " + playerName + " to their current fingerprint and locked their account.", NamedTextColor.GREEN));
            target.sendMessage(Component.text("An admin has manually verified and locked your NameGuard identity.", NamedTextColor.GOLD));
        
        } catch (IOException e) {
            sender.sendMessage(Component.text("An I/O error occurred while retrieving binding. See console.", NamedTextColor.RED));
            plugin.getSLF4JLogger().error("I/O error during /ng bind:", e);
        }
    }

    private void handleCheck(CommandSender sender, String label, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(Component.text("Usage: /" + label + " check <playerName>", NamedTextColor.RED));
            return;
        }
        String playerName = args[1];
        String normalizedName = normalizationUtil.normalizeName(playerName);

        try {
            // This will now load from disk if the player is offline
            bindingManager.getBinding(normalizedName).ifPresentOrElse(binding -> {
                sender.sendMessage(Component.text("--- NameGuard Check: " + binding.getPreferredName() + " ---", NamedTextColor.GOLD));
                sender.sendMessage(Component.text("Normalized: ", NamedTextColor.GRAY).append(Component.text(binding.getNormalizedName(), NamedTextColor.WHITE)));
                sender.sendMessage(Component.text("Type: ", NamedTextColor.GRAY).append(Component.text(binding.getAccountType().name(), NamedTextColor.WHITE)));
                sender.sendMessage(Component.text("Trust: ", NamedTextColor.GRAY).append(Component.text(binding.getTrust().name(), NamedTextColor.WHITE)));
                sender.sendMessage(Component.text("First Seen: ", NamedTextColor.GRAY).append(Component.text(new java.util.Date(binding.getFirstSeen()).toString(), NamedTextColor.WHITE)));
                sender.sendMessage(Component.text("Last Seen: ", NamedTextColor.GRAY).append(Component.text(new java.util.Date(binding.getLastSeen()).toString(), NamedTextColor.WHITE)));
                sender.sendMessage(Component.text("Playtime (ms): ", NamedTextColor.GRAY).append(Component.text(String.valueOf(binding.getTotalPlaytime()), NamedTextColor.WHITE)));
                sender.sendMessage(Component.text("Fingerprints (" + binding.getFingerprints().size() + "):", NamedTextColor.GRAY));

                int i = 1;
                for (Fingerprint fp : binding.getFingerprints()) {
                    sender.sendMessage(Component.text("  --- FP " + i + " (Created: " + new java.util.Date(fp.getCreatedAt()).toString() + ") ---", NamedTextColor.DARK_GRAY));
                    sendInfo(sender, "    XUID", fp.getXuid());
                    sendInfo(sender, "    JavaUUID", fp.getJavaUuid());
                    sendInfo(sender, "    Edition", fp.getEdition().name());
                    
                    // V3 fields
                    sendInfo(sender, "    IP Version", fp.getIpVersion());
                    sendInfo(sender, "    Subnet Hash", fp.getHashedPrefix());
                    sendInfo(sender, "    Pseudo-ASN Hash", fp.getHashedPseudoAsn());
                    sendInfo(sender, "    PTR Hash", fp.getHashedPtr());
                    // End V3
                    
                    sendInfo(sender, "    Device OS", fp.getDeviceOs());
                    sendInfo(sender, "    Brand", fp.getClientBrand());
                    sendInfo(sender, "    Protocol", fp.getProtocolVersion());
                    i++;
                }
            }, () -> {
                sender.sendMessage(Component.text("No binding found for name: " + playerName, NamedTextColor.RED));
            });
            
        } catch (IOException e) {
            sender.sendMessage(Component.text("An I/O error occurred while checking binding. See console.", NamedTextColor.RED));
            plugin.getSLF4JLogger().error("I/O error during /ng check:", e);
        }
    }

    private void sendInfo(CommandSender sender, String key, @Nullable String value) {
        if (value != null) {
            sender.sendMessage(Component.text(key + ": ", NamedTextColor.GRAY).append(Component.text(value, NamedTextColor.WHITE)));
        }
    }

    private void sendHelp(CommandSender sender, String label) {
        sender.sendMessage(Component.text("--- NameGuard Admin ---", NamedTextColor.GOLD));

        Component reloadMsg = Component.text("/" + label + " reload", NamedTextColor.GRAY)
                .append(Component.text(" - Reloads the config.yml.", NamedTextColor.WHITE));
        sender.sendMessage(reloadMsg);

        Component unbindMsg = Component.text("/" + label + " unbind <name>", NamedTextColor.GRAY)
                .append(Component.text(" - Removes identity binding from a name (online or offline).", NamedTextColor.WHITE));
        sender.sendMessage(unbindMsg);

        Component bindMsg = Component.text("/" + label + " bind <onlineName>", NamedTextColor.GRAY)
                .append(Component.text(" - Force-adds the current fingerprint for an online player.", NamedTextColor.WHITE));
        sender.sendMessage(bindMsg);

        Component checkMsg = Component.text("/" + label + " check <name>", NamedTextColor.GRAY)
                .append(Component.text(" - Checks the binding details for a name (online or offline).", NamedTextColor.WHITE));
        sender.sendMessage(checkMsg);
    }

    @Nullable
    @Override
    public List<String> onTabComplete(@NotNull CommandSender sender, @NotNull Command command, @NotNull String label, @NotNull String[] args) {
        if (args.length == 1) {
            return Arrays.asList("reload", "unbind", "bind", "check").stream()
                    .filter(s -> s.startsWith(args[0].toLowerCase()))
                    .collect(Collectors.toList());
        }
        if (args.length == 2 && (args[0].equalsIgnoreCase("unbind") || args[0].equalsIgnoreCase("check"))) {
            // Suggest online players (who are in the cache)
            // Admins can still type offline names
            return bindingManager.getBindingCache().values().stream()
                    .filter(obj -> obj instanceof Binding) // Ensure it's a Binding
                    .map(obj -> ((Binding) obj).getPreferredName())
                    .filter(Objects::nonNull)
                    .filter(name -> name.toLowerCase().startsWith(args[1].toLowerCase()))
                    .collect(Collectors.toList());
        }
        if (args.length == 2 && args[0].equalsIgnoreCase("bind")) {
            // Suggest online players
            return Bukkit.getOnlinePlayers().stream()
                    .map(Player::getName)
                    .filter(name -> name.toLowerCase().startsWith(args[1].toLowerCase()))
                    .collect(Collectors.toList());
        }
        return List.of();
    }
}
