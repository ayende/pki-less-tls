const std = @import("std");
const sodium = @import("../sodium.zig");
const Server = @import("server.zig");

pub const ChallengeResponse = packed struct {
    client_long_term_key: sodium.Encrypted(sodium.key_len),
    challenge_answer: sodium.Encrypted(sodium.key_len),

    pub fn handle(self: *ChallengeResponse, state: *Server) !void {
        try self.client_long_term_key.decrypt(state.client.session_public_key, state.session.secret);

        std.mem.copy(u8, &state.client.long_term_public_key, &self.client_long_term_key.data);

        try self.challenge_answer.decrypt(state.client.long_term_public_key, state.session.secret);

        if (!std.crypto.utils.timingSafeEql([sodium.key_len]u8, state.session.public, self.challenge_answer.data)) {
            return error.InvalidChallengeAnswer;
        }
    }
};
