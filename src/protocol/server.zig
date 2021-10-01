const std = @import("std");
const sodium = @import("../sodium.zig");
usingnamespace @import("hello_message.zig");

const Self = @This();

session: sodium.KeyPair,
long_term: sodium.KeyPair,
client: struct {
    session_public_key: [sodium.key_len]u8,
    long_term_public_key: [sodium.key_len]u8,
},

pub fn initialize(server_long_term_key: sodium.KeyPair) Self {
    return .{
        .session = sodium.KeyPair.init(),
        .long_term = server_long_term_key,
    };
}

pub fn client_public_key(self: *Self, client_session_key: [sodium.key_len]u8) void {
    std.mem.copy(u8, &self.client.session_public_key, &client_session_key);
}

pub fn generateKey(self: *Self) !sodium.SecretKeys {
    return sodium.SecretKeys.generate_server(self.session, self.client.session_public_key);
}
