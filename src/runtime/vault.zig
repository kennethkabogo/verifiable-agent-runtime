const std = @import("std");

/// SecureVault manages sensitive credentials (API keys, private keys) 
/// within the enclave's memory.
pub const SecureVault = struct {
    allocator: std.mem.Allocator,
    secrets: std.StringHashMap([]const u8),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) SecureVault {
        return SecureVault{
            .allocator = allocator,
            .secrets = std.StringHashMap([]const u8).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *SecureVault) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.secrets.iterator();
        while (it.next()) |entry| {
            // Wipe before freeing so secrets don't linger in the allocator's
            // free list.  secureZero uses volatile writes that the compiler
            // cannot legally eliminate.
            std.crypto.utils.secureZero(u8, @constCast(entry.key_ptr.*));
            std.crypto.utils.secureZero(u8, @constCast(entry.value_ptr.*));
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.secrets.deinit();
    }

    /// Stores a secret in the vault. Copies both key and value to internal memory.
    pub fn store(self: *SecureVault, key: []const u8, value: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key_copy = try self.allocator.dupe(u8, key);
        const val_copy = try self.allocator.dupe(u8, value);

        try self.secrets.put(key_copy, val_copy);
    }

    /// Retrieves a secret. Caller must NOT free the returned slice.
    pub fn get(self: *SecureVault, key: []const u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.secrets.get(key);
    }

    /// Drops a secret and wipes memory.
    pub fn drop(self: *SecureVault, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.secrets.fetchRemove(key)) |entry| {
            std.crypto.utils.secureZero(u8, @constCast(entry.key));
            std.crypto.utils.secureZero(u8, @constCast(entry.value));
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
    }
};
