const std = @import("std");
const crypto = @import("../crypto.zig");
const protocol = @import("../protocol.zig");

pub const AuthenticatedConnection = struct {
    stream: crypto.NetworkStream,
    pub_key: [crypto.KeyLength]u8,
};

pub fn clientConnection(
    allocator: *std.mem.Allocator,
    host: []const u8,
    port: u16,
    client_keys: crypto.KeyPair,
    expected_server_key: ?protocol.Client.ExpectedPublicKey,
) !AuthenticatedConnection {
    var con = try std.net.tcpConnectToHost(allocator, host, port);
    errdefer con.close();

    var handshake = protocol.Client.init(client_keys, expected_server_key);
    var hello = try handshake.hello();

    var writer = con.writer();
    try writer.writeAll(std.mem.asBytes(&hello));

    var reader = con.reader();

    var msg: protocol.ChallengeMessage = undefined;
    try reader.readNoEof(std.mem.asBytes(&msg));
    var response = try msg.respond(&handshake);

    try writer.writeAll(std.mem.asBytes(&response));

    var session = try handshake.generateKey();

    var rc: AuthenticatedConnection = undefined;
    std.mem.copy(u8, &rc.pub_key, &handshake.server.long_term_public_key);
    rc.stream = try crypto.NetworkStream.init(allocator, con, session);
    return rc;
}

pub fn serverConnection(allocator: *std.mem.Allocator, stream: std.net.Stream, server_keys: crypto.KeyPair) !AuthenticatedConnection {
    errdefer stream.close();
    var handshake = protocol.Server.initialize(server_keys);

    var reader = stream.reader();
    var hello: protocol.HelloMessage = undefined;
    try reader.readNoEof(std.mem.asBytes(&hello));

    try hello.route(&handshake); // no routing supported here
    var challenge = try hello.challenge(&handshake);

    var writer = stream.writer();
    try writer.writeAll(std.mem.asBytes(&challenge));

    var resp: protocol.ChallengeResponse = undefined;
    try reader.readNoEof(std.mem.asBytes(&resp));

    try resp.completeAuth(&handshake);

    var session = try handshake.generateKey();

    var rc: AuthenticatedConnection = undefined;
    std.mem.copy(u8, &rc.pub_key, &handshake.client.long_term_public_key);
    rc.stream = try crypto.NetworkStream.init(allocator, stream, session);
    return rc;
}
