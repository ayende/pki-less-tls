const std = @import("std");
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");

pub fn authenticate(con: *std.net.StreamServer.Connection, long_term_key: crypto.KeyPair) !void {
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
    try resp.completeAuth(server_state);
    //var secret_keys = server_state.generateKey();
    // std.io.Reader()
}

fn clientFn(host: []const u8, port: u16, server_pub_key: [crypto.KeyLength]u8, client_kp: crypto.KeyPair) !void {
    var server_key = protocol.Client.ExpectedPublicKey{
        .end_public_key = server_pub_key,
        .middlebox_public_key = server_pub_key,
    };
    var con = try crypto.clientConnection(std.heap.page_allocator, host, port, client_kp, server_key);
    std.log.debug("Connected, I'm {s} - other side {s} - expected {s}", .{
        crypto.KeyPair.keyBase64(client_kp.public),
        crypto.KeyPair.keyBase64(con.pub_key),
        crypto.KeyPair.keyBase64(server_pub_key),
    });
    var encrypted_stream = con.stream;
    defer encrypted_stream.deinit();
    var buf: [1024]u8 = undefined;
    var len = try encrypted_stream.reader().read(&buf);
    std.log.debug("{s}", .{buf[0..len]});
    _ = encrypted_stream.reader().read(&buf) catch |e| {
        std.log.debug("err {s}", .{@errorName(e)});
        var a = try encrypted_stream.alert();
        std.log.debug("{s} {s} {s}", .{ @errorName(e), @tagName(a.alert), a.msg });
    };
}

pub fn main() anyerror!void {
    try crypto.init();

    var server_kp = crypto.KeyPair.init();
    var client_kp = crypto.KeyPair.init();

    var server = std.net.StreamServer.init(.{});
    defer server.deinit();

    const localhost = try std.net.Address.parseIp("127.0.0.1", 0);

    try server.listen(localhost);

    const t = try std.Thread.spawn(.{}, clientFn, .{
        "127.0.0.1",
        server.listen_address.getPort(),
        server_kp.public,
        client_kp,
    });

    var client = try server.accept();

    defer t.join();

    var con = try crypto.serverConnection(std.heap.page_allocator, client.stream, server_kp);
    std.log.debug("Connected, I'm {s} - other side {s}", .{
        crypto.KeyPair.keyBase64(server_kp.public),
        crypto.KeyPair.keyBase64(con.pub_key),
    });
    var encrypted_stream = con.stream;
    defer encrypted_stream.deinit();
    var w = encrypted_stream.writer();
    try w.writeAll("hi there");
    try encrypted_stream.flush();

    var msg = "Opps, msg".*;
    try encrypted_stream.send_alert(crypto.AlertTypes.Badness, &msg);

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
