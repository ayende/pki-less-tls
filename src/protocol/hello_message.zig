const std = @import("std");
const crypto = @import("../crypto.zig");
usingnamespace @import("challenge_message.zig");
const Server = @import("server.zig");

pub const ExpectedVersion = 1852142159;

pub const HelloMessage = packed struct {
    version: u32,
    client_session_public_key: [crypto.KeyLength]u8,
    expected_server_public_key: crypto.EncryptedBoxKey,

    pub fn route(self: *HelloMessage, state: *Server) !void {
        state.client_public_key(self.client_session_public_key);

        self.expected_server_public_key.decrypt(self.client_session_public_key, state.long_term.secret) catch {
            // this is fine, if the client doesn't know the public key in advance, that isn't an issue
            return;
        };
        // here, the server have a chance to route the request to another location, where the actual requested key is used.
        // this is done to allow encrypted public key request, so we don't have to expose the actual public key we need.
        if (std.crypto.utils.timingSafeEql([crypto.KeyLength]u8, state.long_term.public, self.expected_server_public_key.data) == false) {
            return error.CannotProvideExpectedPublicKey;
        }
    }

    pub fn challenge(self: *HelloMessage, state: *Server) !ChallengeMessage {
        var c = std.mem.zeroes(ChallengeMessage);

        std.mem.copy(u8, &c.server_session_public_key, &state.session.public);
        std.mem.copy(u8, &c.long_term_key_proof.data, &self.client_session_public_key);
        std.mem.copy(u8, &c.server_long_term_public_key.data, &state.long_term.public);

        try c.long_term_key_proof.encrypt(self.client_session_public_key, state.long_term.secret);
        try c.server_long_term_public_key.encrypt(self.client_session_public_key, state.session.secret);

        return c;
    }
};
