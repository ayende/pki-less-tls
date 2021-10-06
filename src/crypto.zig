const std = @import("std");
const encrypted = @import("crypto/stream.zig");
const sodium = @import("crypto/sodium.zig");
const channel = @import("crypto/channel.zig");

pub const NetworkStream = encrypted.Stream(std.net.Stream);
pub const KeyPair = sodium.KeyPair;
pub const SecretKeys = sodium.SecretKeys;
pub const AlertTypes = encrypted.AlertTypes;
pub const KeyLength = sodium.KeyLen;
pub const EncryptedBoxKey = sodium.EncryptedBoxBuffer(sodium.KeyLen);

pub const clientConnection = channel.clientConnection;
pub const serverConnection = channel.serverConnection;

pub fn init() !void {
    return sodium.init();
}
