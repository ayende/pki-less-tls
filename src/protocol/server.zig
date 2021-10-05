const std = @import("std");
const crypto = @import("../crypto.zig");
usingnamespace @import("hello_message.zig");

const Self = @This();

session: crypto.KeyPair,
long_term: crypto.KeyPair,
client: struct {
    session_public_key: [crypto.KeyLength]u8,
    long_term_public_key: [crypto.KeyLength]u8,
},

pub fn initialize(server_long_term_key: crypto.KeyPair) Self {
    return .{
        .session = crypto.KeyPair.init(),
        .long_term = server_long_term_key,
        .client = undefined,
    };
}

pub fn client_public_key(self: *Self, client_session_key: [crypto.KeyLength]u8) void {
    std.mem.copy(u8, &self.client.session_public_key, &client_session_key);
}

pub fn generateKey(self: *Self) !crypto.SecretKeys {
    return crypto.SecretKeys.generate_server(self.session, self.client.session_public_key);
}
