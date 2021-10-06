const std = @import("std");
const sodium = @import("sodium.zig");
const c = @cImport({
    @cInclude("sodium.h");
});

const RecordBufferSize = 1024 * 16;
const RecordTypes = enum(u8) { Data = 0, Alert = 1 };

pub const AlertTypes = enum(u16) {
    Badness = 1,
    BadChallengeResponse = 2,
};

pub fn Stream(comptime TStream: type) type {
    return struct {
        const Self = @This();

        stream: TStream,
        write: CryptoWriter,
        read: CryptoReader,

        pub const Reader = std.io.Reader(*CryptoReader, anyerror, CryptoReader.read);
        pub const Writer = std.io.Writer(*CryptoWriter, anyerror, CryptoWriter.write);

        pub fn init(allocator: *std.mem.Allocator, stream: TStream, secret_keys: sodium.SecretKeys) !Self {
            errdefer stream.close();

            var self: Self = .{
                .stream = stream,
                .read = undefined,
                .write = undefined,
            };

            // we need the write first, so it will send the header so the other side can read it
            self.write = try CryptoWriter.init(allocator, stream, secret_keys);
            errdefer self.write.deinit();

            self.read = try CryptoReader.init(allocator, stream.reader(), secret_keys);
            errdefer self.read.deinit();

            return self;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = &self.read };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = &self.write };
        }

        pub fn flush(self: *Self) !void {
            return self.write.flush(RecordTypes.Data);
        }

        pub fn alert(self: *Self) !Alert {
            return self.read.alert();
        }

        pub fn send_alert(self: *Self, alert_code: AlertTypes, msg: []u8) !void {
            return self.write.send_alert(alert_code, msg);
        }

        pub fn deinit(self: *Self) void {
            self.write.deinit();
            self.read.deinit();
            self.stream.close();
        }

        pub const CryptoWriter = struct {
            writer: TStream.Writer,
            allocator: *std.mem.Allocator,
            buffer: []u8,
            buffered: usize,
            state: c.crypto_secretstream_xchacha20poly1305_state,
            padder: ?fn (*CryptoWriter, usize) usize,
            alert_raised: bool,
            stream: TStream,

            const HeaderSize = @sizeOf(u16) + @sizeOf(u16) + @sizeOf(u8); // (encrypted len, plain text len, record type)
            const MaxPlainTextSize =
                RecordBufferSize -
                HeaderSize - // encryption overhead
                c.crypto_secretstream_xchacha20poly1305_ABYTES;

            pub fn init(allocator: *std.mem.Allocator, stream: TStream, secret_keys: sodium.SecretKeys) !CryptoWriter {
                var buf = try allocator.alloc(u8, RecordBufferSize * 2);
                errdefer allocator.free(buf);

                var self: CryptoWriter = .{
                    .allocator = allocator,
                    .buffer = buf,
                    .writer = stream.writer(),
                    .padder = null,
                    .stream = stream,
                    .state = undefined,
                    .alert_raised = false,
                    .buffered = 0,
                };

                if (c.crypto_secretstream_xchacha20poly1305_init_push(
                    &self.state,
                    &self.buffer[0],
                    &secret_keys.transmit[0],
                ) != 0) {
                    return error.UnableToPushStreamHeader;
                }

                try self.writer.writeAll(self.buffer[0..c.crypto_secretstream_xchacha20poly1305_HEADERBYTES]);
                self.buffered = HeaderSize;

                return self;
            }

            pub fn flush(self: *CryptoWriter, rec_type: RecordTypes) !void {
                if (self.alert_raised) {
                    return error.AlertAlreadyRaised;
                }
                if (self.buffered > MaxPlainTextSize) {
                    return error.PlainTextRecordSizeToLarge; // should never happen
                }
                std.mem.writeInt(u16, self.buffer[2..4], @intCast(u16, self.buffered - @sizeOf(u16)), .Little);
                self.buffer[4] = @enumToInt(rec_type);
                if (self.padder) |padder| {
                    var pad_len = padder(self, self.buffered);
                    if (pad_len + self.buffered > MaxPlainTextSize)
                        return error.InvalidPaddingLengthProvided;
                    std.mem.set(u8, self.buffer[self.buffered..(self.buffered + pad_len)], 0);
                    self.buffered += pad_len;
                }
                var len: u64 = 0;
                var encrypted = self.buffer[RecordBufferSize..];
                if (c.crypto_secretstream_xchacha20poly1305_push(
                    &self.state,
                    &encrypted[@sizeOf(u16)],
                    &len,
                    &self.buffer[@sizeOf(u16)],
                    self.buffered - @sizeOf(u16),
                    null,
                    0,
                    0,
                ) != 0) {
                    return error.UnableToPushEncryptedRecord;
                }
                if (len > RecordBufferSize - @sizeOf(u16)) {
                    return error.EncryptedRecordSizeTooBig; // should never happen
                }
                std.mem.writeInt(u16, encrypted[0..2], @intCast(u16, len + @sizeOf(u16)), .Little);
                try self.writer.writeAll(encrypted[0 .. len + @sizeOf(u16)]);
                self.buffered = HeaderSize;
            }

            pub fn send_alert(self: *CryptoWriter, alert_type: AlertTypes, msg: []u8) !void {
                defer {
                    self.alert_raised = true;
                }
                if (msg.len + @sizeOf(AlertTypes) + @sizeOf(u16) > MaxPlainTextSize) {
                    return error.PlainTextRecordSizeToLarge;
                }
                std.mem.copy(u8, self.buffer[(HeaderSize + @sizeOf(AlertTypes))..], msg);
                std.mem.writeInt(u16, self.buffer[HeaderSize .. HeaderSize + @sizeOf(u16)], @enumToInt(alert_type), .Little);
                self.buffered = HeaderSize + @sizeOf(AlertTypes) + msg.len; // we discard everything else
                try self.flush(RecordTypes.Alert);
            }

            pub fn write(self: *CryptoWriter, buffer: []const u8) !usize {
                if (self.alert_raised) {
                    return error.AlertAlreadyRaised;
                }
                var buf = buffer;
                var total_size: usize = 0;
                while (true) {
                    var size = std.math.min(buf.len, RecordBufferSize - self.buffered);
                    total_size += size;
                    std.mem.copy(u8, self.buffer[self.buffered..RecordBufferSize], buf[0..size]);
                    self.buffered += size;
                    buf = buf[size..];
                    if (self.buffered == RecordBufferSize) {
                        try self.flush(RecordTypes.Data);
                    }
                    if (buf.len == 0)
                        break;
                }
                return total_size;
            }

            pub fn deinit(self: *CryptoWriter) void {
                std.mem.set(u8, self.buffer, 0);
                self.allocator.free(self.buffer);
            }
        };

        pub const Alert = struct {
            alert: AlertTypes,
            msg: []u8,
        };

        pub const CryptoReader = struct {
            reader: TStream.Reader,
            allocator: *std.mem.Allocator,
            buffer: []u8, // 1st half cipher text, 2nd  plain text
            incoming: []u8,
            incoming_plain_text: []u8,
            state: c.crypto_secretstream_xchacha20poly1305_state,
            alert_code: ?AlertTypes,

            pub fn init(allocator: *std.mem.Allocator, source: TStream.Reader, secret_keys: sodium.SecretKeys) !CryptoReader {
                var buf = try allocator.alloc(u8, RecordBufferSize * 2);
                errdefer allocator.free(buf);
                var self: CryptoReader = .{
                    .allocator = allocator,
                    .reader = source,
                    .buffer = buf,
                    .incoming = &[0]u8{},
                    .incoming_plain_text = &[0]u8{},
                    .state = undefined,
                    .alert_code = null,
                };

                while (self.incoming.len < c.crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
                    try self.read_from_network();
                }

                if (c.crypto_secretstream_xchacha20poly1305_init_pull(
                    &self.state,
                    &self.incoming[0],
                    &secret_keys.recieve[0],
                ) != 0) {
                    return error.FailedToInitCryptoStream;
                }

                std.mem.copy(u8, self.incoming, self.incoming[c.crypto_secretstream_xchacha20poly1305_HEADERBYTES..]);
                self.incoming = self.incoming[c.crypto_secretstream_xchacha20poly1305_HEADERBYTES..];
                return self;
            }

            pub fn deinit(self: *CryptoReader) void {
                std.mem.set(u8, self.buffer, 0);
                self.allocator.free(self.buffer);
            }

            pub fn alert(self: *CryptoReader) !Alert {
                if (self.alert_code) |code| {
                    var rc = Alert{ .alert = code, .msg = self.incoming_plain_text };
                    return rc;
                }
                return error.NoAlertRecieved;
            }

            fn read_buffer(self: *CryptoReader, buffer: []u8) usize {
                var size = std.math.min(self.incoming_plain_text.len, buffer.len);
                std.mem.copy(u8, buffer, self.incoming_plain_text[0..size]);
                self.incoming_plain_text = self.incoming_plain_text[size..];
                return size;
            }

            fn read_from_network(self: *CryptoReader) !void {
                var existing = self.incoming.len; // we may have data already in buffer, but need more...
                var len = try self.reader.read(self.buffer[existing..(RecordBufferSize - existing)]);
                if (len == 0) {
                    return error.UnexpectedEndOfStream;
                }
                self.incoming = self.buffer[0..(existing + len)];
            }

            fn read(self: *CryptoReader, buffer: []u8) !usize {
                if (self.alert_code) |_| {
                    return error.AnAlertWasRaised;
                }
                if (self.incoming_plain_text.len > 0) { // read from buffer
                    return self.read_buffer(buffer);
                }
                while (true) {
                    while (self.incoming.len < @sizeOf(u16)) {
                        try self.read_from_network();
                    }
                    var env_len = std.mem.readInt(u16, self.incoming[0..2], .Little);
                    if (env_len == 0 or env_len > RecordBufferSize) {
                        return error.InvalidCryptoEnvelopeSize;
                    }
                    while (env_len > self.incoming.len) {
                        try self.read_from_network(); // read enough bytes from network
                    }
                    self.incoming_plain_text = self.buffer[RecordBufferSize..];
                    var len: u64 = 0;
                    if (c.crypto_secretstream_xchacha20poly1305_pull(
                        &self.state,
                        &self.incoming_plain_text[0],
                        &len,
                        null,
                        &self.incoming[@sizeOf(u16)],
                        env_len - @sizeOf(u16),
                        null,
                        0,
                    ) != 0) {
                        return error.FailedToDecryptRecord;
                    }
                    std.mem.copy(u8, self.incoming, self.incoming[env_len..]);
                    self.incoming = self.incoming[env_len..];
                    if (len < @sizeOf(u16)) {
                        return error.DecryptedRecordIsTooSmall;
                    }
                    var plain_txt_len = std.mem.readInt(u16, self.incoming_plain_text[0..2], .Little);
                    if (plain_txt_len == 0) {
                        continue; // allowed to have empty record
                    }
                    var record_type = @intToEnum(RecordTypes, self.incoming_plain_text[@sizeOf(u16)]);
                    self.incoming_plain_text = self.incoming_plain_text[@sizeOf(u16) + @sizeOf(u8) .. plain_txt_len];
                    if (record_type == .Alert) {
                        self.alert_code = @intToEnum(AlertTypes, std.mem.readInt(u16, self.incoming_plain_text[0..@sizeOf(u16)], .Little));
                        self.incoming_plain_text = self.incoming_plain_text[@sizeOf(u16)..];
                        return error.AnAlertWasRaised;
                    }
                    break;
                }
                return self.read_buffer(buffer);
            }
        };
    };
}
