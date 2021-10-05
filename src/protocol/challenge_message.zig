const std = @import("std");
const crypto = @import("../crypto.zig");
const Client = @import("client.zig");

const ChallengeResponse = @import("challenge_response.zig").ChallengeResponse;

pub const ChallengeMessage = packed struct {
    server_session_public_key: [crypto.KeyLength]u8,
    server_long_term_public_key: crypto.EncryptedBoxKey,
    long_term_key_proof: crypto.EncryptedBoxKey,

    pub fn respond(self: *ChallengeMessage, state: *Client) !ChallengeResponse {
        var resp = std.mem.zeroes(ChallengeResponse);
        std.mem.copy(u8, &state.server.session_public_key, &self.server_session_public_key);

        try self.server_long_term_public_key.decrypt(self.server_session_public_key, state.session.secret);

        std.mem.copy(u8, &state.server.long_term_public_key, &self.server_long_term_public_key.data);

        if (state.server.validate_server_key) {
            if (!std.crypto.utils.timingSafeEql(
                [crypto.KeyLength]u8,
                state.server.expected_server_key.end_public_key,
                state.server.long_term_public_key,
            )) {
                return error.ExpectedServerPublicKeyMismatch;
            }
        }

        try self.long_term_key_proof.decrypt(state.server.long_term_public_key, state.session.secret);

        if (!std.crypto.utils.timingSafeEql([crypto.KeyLength]u8, self.long_term_key_proof.data, state.session.public)) {
            return error.LongTermProofValueAndSessionPublicKeyMismatch;
        }

        std.mem.copy(u8, &resp.client_long_term_key.data, &state.long_term.public);
        try resp.client_long_term_key.encrypt(state.server.session_public_key, state.session.secret);

        std.mem.copy(u8, &resp.challenge_answer.data, &state.server.session_public_key);
        try resp.challenge_answer.encrypt(state.server.session_public_key, state.long_term.secret);

        return resp;
    }
};
