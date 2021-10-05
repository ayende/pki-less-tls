const std = @import("std");
const crypto = @import("../crypto.zig");
const Server = @import("server.zig");

pub const ChallengeResponse = packed struct {
    client_long_term_key: crypto.EncryptedBoxKey,
    challenge_answer: crypto.EncryptedBoxKey,

    pub fn completeAuth(self: *ChallengeResponse, state: *Server) !void {
        try self.client_long_term_key.decrypt(state.client.session_public_key, state.session.secret);

        std.mem.copy(u8, &state.client.long_term_public_key, &self.client_long_term_key.data);

        try self.challenge_answer.decrypt(state.client.long_term_public_key, state.session.secret);

        if (!std.crypto.utils.timingSafeEql([crypto.KeyLength]u8, state.session.public, self.challenge_answer.data)) {
            return error.InvalidChallengeAnswer;
        }
    }
};
