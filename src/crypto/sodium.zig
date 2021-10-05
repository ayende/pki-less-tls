const std = @import("std");

const c = @cImport({
    @cInclude("sodium.h");
});

pub fn init() !void {
    if (c.sodium_init() < 0) {
        return error.InitError;
    }
}

const base64_variant = c.sodium_base64_VARIANT_URLSAFE_NO_PADDING;

pub const KeyLen = 32;
comptime {
    if (KeyLen != c.crypto_box_PUBLICKEYBYTES or KeyLen != c.crypto_box_SECRETKEYBYTES) {
        @compileError("KeyLen should match crypto_box_PUBLICKEYBYTE and crypto_box_SECRETKEYBYTES");
    }
}
pub const key_b64_len = c.sodium_base64_ENCODED_LEN(KeyLen, base64_variant);
pub const nonce_len = c.crypto_box_NONCEBYTES;
pub const mac_len = c.crypto_box_MACBYTES;

pub fn randombytes(data: []u8) void {
    c.randombytes_buf(&data[0], data.len);
}

pub fn EncryptedBoxBuffer(size: usize) type {
    return packed struct {
        const Self = @This();

        data: [size]u8,
        mac: [mac_len]u8,
        nonce: [nonce_len]u8,

        pub fn encrypt(
            self: *Self,
            public_key: [KeyLen]u8,
            secret_key: [KeyLen]u8,
        ) !void {
            c.randombytes_buf(&self.nonce, self.nonce.len);
            var rc = c.crypto_box_detached(
                &self.data[0],
                &self.mac,
                &self.data[0],
                size,
                &self.nonce,
                &public_key,
                &secret_key,
            );
            if (rc != 0) {
                return error.EncryptionFailure;
            }
        }
        pub fn decrypt(
            self: *Self,
            public_key: [KeyLen]u8,
            secret_key: [KeyLen]u8,
        ) !void {
            var rc = c.crypto_box_open_detached(
                &self.data[0],
                &self.data[0],
                &self.mac,
                size,
                &self.nonce,
                &public_key,
                &secret_key,
            );
            if (rc != 0) {
                return error.DecryptionFailure;
            }
        }
    };
}

pub const SecretKeys = struct {
    recieve: [KeyLen]u8,
    transmit: [KeyLen]u8,

    pub fn generate() SecretKeys {
        var rc: SecretKeys = undefined;
        c.crypto_secretstream_xchacha20poly1305_keygen(&rc.recieve);
        c.crypto_secretstream_xchacha20poly1305_keygen(&rc.transmit);
        return rc;
    }

    pub fn inverse(self: *SecretKeys) SecretKeys {
        return .{
            .transmit = self.recieve,
            .recieve = self.transmit,
        };
    }

    pub fn generate_client(client: KeyPair, server_public_key: [KeyLen]u8) !SecretKeys {
        var rc: SecretKeys = undefined;
        if (c.crypto_kx_client_session_keys(
            &rc.recieve[0],
            &rc.transmit[0],
            &client.public[0],
            &client.secret[0],
            &server_public_key[0],
        ) != 0) {
            return error.FailedToGenerateKey;
        }
        return rc;
    }

    pub fn generate_server(server: KeyPair, client_public_key: [KeyLen]u8) !SecretKeys {
        var rc: SecretKeys = undefined;
        if (c.crypto_kx_server_session_keys(
            &rc.recieve[0],
            &rc.transmit[0],
            &server.public[0],
            &server.secret[0],
            &client_public_key[0],
        ) != 0) {
            return error.FailedToGenerateKey;
        }
        return rc;
    }
};

pub const KeyPair = struct {
    public: [KeyLen]u8,
    secret: [KeyLen]u8,

    pub const Base64 = struct {
        public: [key_b64_len]u8,
        secret: [key_b64_len]u8,
    };

    pub fn from(public_key_b64: *const [key_b64_len - 1:0]u8, secret_key_b64: *const [key_b64_len - 1:0]u8) KeyPair {
        var kp: KeyPair = undefined;
        var len: usize = 0;
        _ = c.sodium_base642bin(
            &kp.public[0],
            kp.public.len,
            &public_key_b64[0],
            public_key_b64.len,
            null,
            &len,
            null,
            base64_variant,
        );
        std.debug.assert(len == kp.public.len);
        _ = c.sodium_base642bin(
            &kp.secret[0],
            kp.secret.len,
            &secret_key_b64[0],
            secret_key_b64.len,
            null,
            &len,
            null,
            base64_variant,
        );
        std.debug.assert(len == kp.secret.len);
        return kp;
    }

    pub fn keyBase64(key: [KeyLen]u8) [key_b64_len]u8 {
        var key_b64: [key_b64_len]u8 = undefined;
        _ = c.sodium_bin2base64(&key_b64, key_b64_len, &key, KeyLen, base64_variant);
        return key_b64;
    }

    pub fn init() KeyPair {
        var r: KeyPair = undefined;
        if (c.crypto_box_keypair(&r.public, &r.secret) != 0) {
            @panic("crypto_box_keypair cannot happen");
        }
        return r;
    }

    pub fn base64(self: *KeyPair) Base64 {
        var result: Base64 = undefined;
        _ = c.sodium_bin2base64(&result.secret, key_b64_len, &self.secret, KeyLen, base64_variant);
        _ = c.sodium_bin2base64(&result.public, key_b64_len, &self.public, KeyLen, base64_variant);
        return result;
    }
};
