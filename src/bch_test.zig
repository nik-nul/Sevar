const std = @import("std");
const bch = @import("bch.zig");

const BchControl = bch.BchControl;

fn makeBch(m: u32, t: u32) !*BchControl {
    return BchControl.init(m, t, 0);
}

fn makeBchPrim(m: u32, t: u32, prim: u32) !*BchControl {
    return BchControl.init(m, t, prim);
}

fn sortU32(xs: []u32) void {
    std.mem.sort(u32, xs, {}, comptime std.sort.asc(u32));
}

test "known bit vectors from bch_codec" {
    // m=5, t=2, prim=0x25 (37), n=31, k=21.
    const b = try makeBchPrim(5, 2, 37);
    defer b.deinit();

    const msgs = [_][]const u8{
        "100000000000000000000",
        "010000000000000000000",
        "001000000000000000000",
        "100100000000000000000",
        "010010000000000000000",
        "101001000000000000000",
        "110100100000000000000",
        "011010010000000000000",
        "101101001000000000000",
        "110110100100000000000",
        "111011010010000000000",
        "011101101001000000000",
        "001110110100100000000",
        "000111011010010000000",
        "000011101101001000000",
        "000001110110100100000",
        "000000111011010010000",
        "000000011101101001000",
        "000000001110110100100",
        "000000000111011010010",
        "000000000011101101001",
    };
    const expected = [_][]const u8{
        "1110110100", "0111011010", "0011101101", "0001110110", "0000111011",
        "0000011101", "0000001110", "0000000111", "0000000011", "0000000001",
        "0000000000", "0000000000", "0000000000", "0000000000", "0000000000",
        "0000000000", "0000000000", "0000000000", "0000000000", "0000000000",
        "0000000000",
    };

    try std.testing.expectEqual(@as(usize, 21), b.dataBits());
    try std.testing.expectEqual(@as(usize, 10), b.eccBits());

    for (msgs, expected) |msg, want| {
        var data: [21]u8 = undefined;
        for (msg, 0..) |ch, i| data[i] = ch - '0';
        var got: [10]u8 = @splat(0);
        b.encodeBits(&data, &got);
        for (want, 0..) |ch, i| {
            try std.testing.expectEqual(@as(u8, ch - '0'), got[i]);
        }
    }
}

fn roundtrip(m: u32, t: u32, seed: u64) !void {
    const b = try makeBch(m, t);
    defer b.deinit();

    const kbytes = b.blockBytes();
    const ecc_bytes = b.eccBytes();
    const allocator = std.testing.allocator;

    const clean = try allocator.alloc(u8, kbytes);
    defer allocator.free(clean);
    const data = try allocator.alloc(u8, kbytes);
    defer allocator.free(data);
    const ecc = try allocator.alloc(u8, ecc_bytes);
    defer allocator.free(ecc);
    const errloc = try allocator.alloc(u32, b.errorCapacity());
    defer allocator.free(errloc);

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    random.bytes(clean);
    @memcpy(data, clean);

    @memset(ecc, 0);
    b.encode(data, ecc);

    var nerr = try b.decode(data, ecc, errloc);
    try std.testing.expectEqual(@as(usize, 0), nerr);

    var expected: [64]u32 = undefined;
    const nflip: usize = if (t > 0 and kbytes > 0) random.uintLessThan(usize, t + 1) else 0;
    try std.testing.expect(nflip <= expected.len);

    var placed: usize = 0;
    while (placed < nflip) {
        const bit = random.uintLessThan(usize, kbytes * 8);
        var duplicate = false;
        for (expected[0..placed]) |prev| {
            if (prev == bit) duplicate = true;
        }
        if (duplicate) continue;
        expected[placed] = @intCast(bit);
        placed += 1;
        data[bit >> 3] ^= @as(u8, 1) << @intCast(bit & 7);
    }

    nerr = try b.decode(data, ecc, errloc);
    try std.testing.expectEqual(nflip, nerr);

    sortU32(expected[0..nflip]);
    sortU32(errloc[0..nflip]);
    try std.testing.expectEqualSlices(u32, expected[0..nflip], errloc[0..nflip]);

    b.correct(data, errloc[0..nerr]);
    try std.testing.expectEqualSlices(u8, clean, data);
}

test "random roundtrip across supported fields" {
    const cases = [_][2]u32{
        .{ 5, 1 },  .{ 5, 3 },   .{ 5, 6 },
        .{ 6, 1 },  .{ 6, 3 },   .{ 6, 5 },
        .{ 7, 1 },  .{ 7, 4 },   .{ 7, 8 },
        .{ 8, 1 },  .{ 8, 4 },   .{ 8, 8 },
        .{ 9, 1 },  .{ 9, 5 },   .{ 9, 10 },
        .{ 10, 1 }, .{ 10, 5 },  .{ 10, 10 },
        .{ 11, 1 }, .{ 11, 6 },  .{ 11, 12 },
        .{ 12, 1 }, .{ 12, 8 },  .{ 12, 16 },
        .{ 13, 1 }, .{ 13, 8 },  .{ 13, 20 },
        .{ 14, 1 }, .{ 14, 10 }, .{ 14, 25 },
        .{ 15, 1 }, .{ 15, 12 }, .{ 15, 30 },
    };
    for (cases, 0..) |case, i| {
        try roundtrip(case[0], case[1], 0x1234_5678 + i * 7919);
    }
}

test "bitwise roundtrip and correction" {
    const b = try makeBch(9, 5);
    defer b.deinit();

    const kbits = b.dataBits();
    const ecc_bits = b.eccBits();
    const allocator = std.testing.allocator;
    const clean = try allocator.alloc(u8, kbits);
    defer allocator.free(clean);
    const data = try allocator.alloc(u8, kbits);
    defer allocator.free(data);
    const ecc = try allocator.alloc(u8, ecc_bits);
    defer allocator.free(ecc);
    const errloc = try allocator.alloc(u32, b.errorCapacity());
    defer allocator.free(errloc);

    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    for (clean) |*v| v.* = random.int(u8) & 1;
    @memcpy(data, clean);

    b.encodeBits(data, ecc);
    var nerr = try b.decodeBits(data, ecc, errloc);
    try std.testing.expectEqual(@as(usize, 0), nerr);

    const flips = [_]u32{ 0, 7, 100, @intCast(kbits / 2), @intCast(kbits - 1) };
    for (flips) |bit| data[bit] ^= 1;

    const expected = [_]u32{ 0, 7, 100, @intCast(kbits / 2), @intCast(kbits - 1) };
    nerr = try b.decodeBits(data, ecc, errloc);
    try std.testing.expectEqual(flips.len, nerr);
    sortU32(errloc[0..flips.len]);
    try std.testing.expectEqualSlices(u32, &expected, errloc[0..flips.len]);

    b.correctBits(data, errloc[0..nerr]);
    try std.testing.expectEqualSlices(u8, clean, data);
}

test "incremental encoding matches one-shot encoding" {
    const b = try makeBch(10, 3);
    defer b.deinit();

    const len = b.blockBytes();
    const allocator = std.testing.allocator;
    const clean = try allocator.alloc(u8, len);
    defer allocator.free(clean);
    // One extra leading byte keeps the encoded buffer unaligned.
    const raw = try allocator.alloc(u8, len + 1);
    defer allocator.free(raw);
    const ecc = try allocator.alloc(u8, b.eccBytes());
    defer allocator.free(ecc);
    const ecc2 = try allocator.alloc(u8, b.eccBytes());
    defer allocator.free(ecc2);
    const errloc = try allocator.alloc(u32, b.errorCapacity());
    defer allocator.free(errloc);

    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(clean);
    @memcpy(raw[1..], clean);

    @memset(ecc, 0);
    b.encode(raw[1..], ecc);

    // Incremental encoding must produce the same parity.
    @memset(ecc2, 0);
    const half = len / 2;
    b.encode(raw[1..][0..half], ecc2);
    b.encode(raw[1 + half ..][0 .. len - half], ecc2);
    try std.testing.expectEqualSlices(u8, ecc, ecc2);

    var nerr = try b.decode(raw[1..], ecc, errloc);
    try std.testing.expectEqual(@as(usize, 0), nerr);

    const flips = [_]usize{ 0, 5, len - 1 };
    for (flips) |bit| {
        raw[1 + (bit >> 3)] ^= @as(u8, 1) << @intCast(bit & 7);
    }

    nerr = try b.decode(raw[1..], ecc, errloc);
    try std.testing.expectEqual(flips.len, nerr);
    b.correct(raw[1..], errloc[0..nerr]);
    try std.testing.expectEqualSlices(u8, clean, raw[1..]);
}

test "decode rejects invalid slices" {
    const b = try makeBch(8, 4);
    defer b.deinit();

    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, b.dataBytes() + 1);
    defer allocator.free(data);
    @memset(data, 0);
    const ecc = try allocator.alloc(u8, b.eccBytes());
    defer allocator.free(ecc);
    @memset(ecc, 0);
    const errloc = try allocator.alloc(u32, b.errorCapacity());
    defer allocator.free(errloc);

    const block = data[0..b.blockBytes()];
    try std.testing.expectError(error.InvalidParameters, b.decode(data, ecc, errloc));
    try std.testing.expectError(error.InvalidParameters, b.decode(block, ecc[0 .. b.eccBytes() - 1], errloc));
    try std.testing.expectError(error.InvalidParameters, b.decode(block, ecc, errloc[0 .. b.errorCapacity() - 1]));
}

test "invalid parameters are rejected" {
    try std.testing.expectError(error.InvalidParameters, BchControl.init(4, 1, 0));
    try std.testing.expectError(error.InvalidParameters, BchControl.init(16, 1, 0));
    try std.testing.expectError(error.InvalidParameters, BchControl.init(5, 0, 0));

    // m*t must stay strictly below n = 2^m - 1.
    try std.testing.expectError(error.InvalidParameters, BchControl.init(5, 7, 0));
    try std.testing.expectError(error.InvalidParameters, BchControl.init(8, 32, 0));

    // Degree-correct but reducible polynomial: x^5 + 1.
    try std.testing.expectError(error.InvalidPrimitivePolynomial, BchControl.init(5, 2, 0x21));

    const b = try BchControl.init(8, 31, 0);
    defer b.deinit();
    try std.testing.expectEqual(@as(u32, 255), b.n);
}
