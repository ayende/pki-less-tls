const std = @import("std");
const protocol = @import("protocol.zig");
const sodium = @import("sodium.zig");

// pub const CryptoStream = struct {
//     secret_keys : sodium.SecretKeys,
//     network : std.net.Stream,

//     pub const Reader = std.io.Reader(*CryptoStream, anyerror, read);
//     pub const Writer = std.io.Writer(*CryptoStream, anyerror, write);

//     fn read(context: *CryptoStream, buffer: []u8) !usize{
//         var len = try std.net.Stream.read(context, buffer);
//         secret_keys.
//     }
// }

pub fn authenticate(con: *std.net.StreamServer.Connection, long_term_key: sodium.KeyPair) !void {
    var server_state = protocol.Server.initialize(long_term_key);
    var reader = con.stream.reader();
    var writer = con.stream.writer();
    var hello: protocol.HelloMessage = undefined;
    try reader.readNoEof(std.mem.asBytes(&hello));
    try hello.route(server_state);
    var challenge = try hello.challenge(server_state);
    try writer.writeAll(std.mem.asBytes(&challenge));
    var resp: protocol.ChallengeResponse = undefined;
    try reader.readNoEof(std.mem.asBytes(&resp));
    try resp.handle(server_state);
    // var secret_keys = server_state.generateKey();
    // std.io.Reader()
}

pub fn main() anyerror!void {
    try sodium.init();

    var state : c.crypto_secretstream_xchacha20poly1305_state = undefined;
    var key : [c.crypto_secretstream_xchacha20poly1305_KEYBYTES]u8 = undefined;
    var header :

    // var sltk = sodium.KeyPair.init();
    // var b64 = sltk.base64();
    // std.log.debug("{s} / {s}", .{ b64.secret, b64.public });

    // var options = std.net.StreamServer.Options{};
    // var server = std.net.StreamServer.init(options);
    // try server.listen(try std.net.Address.parseIp("0.0.0.0", 3587));
    // defer server.deinit();

    // while (true) {
    //     var con = try server.accept();
    //     defer con.stream.close();

    //     try authenticate(con, sltk);
    // }

    // var server_state: protocol.Server = undefined;
    // server_state.initialize(sltk);

    // var cltk = sodium.KeyPair.init();

    // var client_state = protocol.Client.init(cltk, null);

    // var hello_req = try client_state.hello();

    // try hello_req.route(&server_state);

    // var challenge = try hello_req.challenge(&server_state);

    // var resp = try challenge.respond(&client_state);

    // try resp.handle(&server_state);

    // var ck = try client_state.generateKey();
    // var sk = try server_state.generateKey();

    // std.log.debug("server -> client (client pov): {s}", .{sodium.KeyPair.keyBase64(ck.recieve)});
    // std.log.debug("server -> client (server pov): {s}", .{sodium.KeyPair.keyBase64(sk.transmit)});

    // std.log.debug("server <- client (client pov): {s}", .{sodium.KeyPair.keyBase64(ck.transmit)});
    // std.log.debug("server <- client (server pov): {s}", .{sodium.KeyPair.keyBase64(sk.recieve)});
}
