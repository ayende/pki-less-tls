const std = @import("std");
usingnamespace @import("hello_message.zig");
const crypto = @import("../crypto.zig");

const Client = @This();

pub const ExpectedPublicKey = struct {
    end_public_key: [crypto.KeyLength]u8,
    middlebox_public_key: [crypto.KeyLength]u8,

    pub fn generate_fake() ExpectedPublicKey {
        // we generate key pairs and discard them immediately, just to ensure
        // that we can get valid public keys, but ones that aren't valuable
        var t = crypto.KeyPair.init();
        var result: ExpectedPublicKey = undefined;
        std.mem.copy(u8, &result.end_public_key, &t.public);
        t = crypto.KeyPair.init();
        std.mem.copy(u8, &result.middlebox_public_key, &t.public);
        return result;
    }
};

session: crypto.KeyPair,
long_term: crypto.KeyPair,
server: struct {
    session_public_key: [crypto.KeyLength]u8,
    long_term_public_key: [crypto.KeyLength]u8,
    expected_server_key: ExpectedPublicKey,
    validate_server_key: bool,
},

pub fn init(client_long_term_key: crypto.KeyPair, expected_server_key: ?ExpectedPublicKey) Client {
    var r: Client = undefined;
    r.session = crypto.KeyPair.init();
    r.long_term = client_long_term_key;
    r.server.expected_server_key = if (expected_server_key) |k| k else ExpectedPublicKey.generate_fake();
    r.server.validate_server_key = expected_server_key != null;
    return r;
}

pub fn generateKey(self: *Client) !crypto.SecretKeys {
    return crypto.SecretKeys.generate_client(self.session, self.server.session_public_key);
}

pub fn hello(self: *Client) !HelloMessage {
    var req: HelloMessage = undefined;
    req.version = Client.ExpectedVersion;
    std.mem.copy(u8, &req.client_session_public_key, &self.session.public);
    std.mem.copy(u8, &req.expected_server_public_key.data, &self.server.expected_server_key.end_public_key);
    try req.expected_server_public_key.encrypt(self.server.expected_server_key.middlebox_public_key, self.session.secret);
    return req;
}
