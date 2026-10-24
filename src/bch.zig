const std = @import("std");

/// Errors reported while decoding a block.
pub const DecodeError = error{
    /// The supplied slices are too short or otherwise inconsistent.
    InvalidParameters,
    /// The block has more errors than the code can correct.
    Uncorrectable,
};

const min_m: u32 = 5;
const max_m: u32 = 15;

/// Default primitive polynomials for m = 5..15.
const default_prim_polys = [_]u32{
    0x25, 0x43, 0x83, 0x11d, 0x211, 0x409, 0x805, 0x1053, 0x201b, 0x402b, 0x8003,
};

fn divRoundUp(n: u32, d: u32) u32 {
    return (n + d - 1) / d;
}

/// Index of the most significant set bit. x must be non-zero.
fn polyDegree(x: u32) u5 {
    std.debug.assert(x != 0);
    return @intCast(31 - @clz(x));
}

fn bitParity(x: u32) u32 {
    return @intCast(@popCount(x) & 1);
}

/// A polynomial over GF(2^m).
///
/// Coefficients are stored in c[0..deg], little-endian with respect to the
/// exponent (c[i] is the coefficient of X^i). The backing storage may be
/// larger than deg + 1; this is used by the Berlekamp trace factorisation
/// to split a polynomial in place without allocating.
pub const Poly = struct {
    c: []u32,
    deg: u32 = 0,

    fn init(storage: []u32) Poly {
        return .{ .c = storage, .deg = 0 };
    }

    fn clear(self: *Poly) void {
        @memset(self.c, 0);
        self.deg = 0;
    }

    fn copyFrom(self: *Poly, src: *const Poly) void {
        std.debug.assert(self.c.len >= src.deg + 1);
        self.deg = src.deg;
        @memcpy(self.c[0 .. src.deg + 1], src.c[0 .. src.deg + 1]);
    }

    fn trim(self: *Poly) void {
        while (self.deg != 0 and self.c[self.deg] == 0) self.deg -= 1;
    }
};

/// Runtime BCH codec state.
///
/// The public fields m, n, t, ecc_bits and ecc_bytes describe the
/// code; all other fields are implementation details.
pub const BchControl = struct {
    m: u32,
    n: u32,
    t: u32,
    ecc_bits: u32,
    ecc_bytes: u32,

    a_pow_tab: []u16,
    a_log_tab: []u16,
    mod8_tab: []u32,
    ecc_buf: []u32,
    ecc_buf2: []u32,
    xi_tab: []u32,
    syn: []u32,
    cache: []i32,

    elp: Poly,
    poly_2t: [4]Poly,

    databuf: []u8,
    arena: std.heap.ArenaAllocator,

    pub fn eccWords(self: *const BchControl) u32 {
        return divRoundUp(self.m * self.t, 32);
    }

    /// Number of data bits in a block.
    pub fn dataBits(self: *const BchControl) usize {
        return @intCast(self.n - self.ecc_bits);
    }

    /// Number of data bytes in a block, including a partial final byte.
    pub fn dataBytes(self: *const BchControl) usize {
        return @intCast(divRoundUp(self.n - self.ecc_bits, 8));
    }

    /// Number of whole data bytes available to byte-oriented callers.
    pub fn blockBytes(self: *const BchControl) usize {
        return self.dataBits() / 8;
    }

    /// Number of parity bits in a block.
    pub fn eccBits(self: *const BchControl) usize {
        return @intCast(self.ecc_bits);
    }

    /// Number of parity bytes in a block.
    pub fn eccBytes(self: *const BchControl) usize {
        return @intCast(self.ecc_bytes);
    }

    /// Maximum number of correctable bit errors.
    pub fn errorCapacity(self: *const BchControl) usize {
        return @intCast(self.t);
    }

    // ---------------------------------------------------------------------
    // GF(2^m) arithmetic
    // ---------------------------------------------------------------------

    fn modS(self: *const BchControl, v: u32) u32 {
        return if (v < self.n) v else v - self.n;
    }

    fn modulo(self: *const BchControl, v: u32) u32 {
        var x = v;
        while (x >= self.n) {
            x -= self.n;
            x = (x & self.n) + (x >> @intCast(self.m));
        }
        return x;
    }

    fn aPow(self: *const BchControl, i: u32) u32 {
        return self.a_pow_tab[self.modulo(i)];
    }

    fn aLog(self: *const BchControl, x: u32) u32 {
        return self.a_log_tab[x];
    }

    fn aIlog(self: *const BchControl, x: u32) u32 {
        return self.modS(self.n - self.aLog(x));
    }

    fn gfMul(self: *const BchControl, a: u32, b: u32) u32 {
        if (a == 0 or b == 0) return 0;
        return self.a_pow_tab[self.modS(self.aLog(a) + self.aLog(b))];
    }

    fn gfSqr(self: *const BchControl, a: u32) u32 {
        if (a == 0) return 0;
        return self.a_pow_tab[self.modS(2 * self.aLog(a))];
    }

    fn gfDiv(self: *const BchControl, a: u32, b: u32) u32 {
        if (a == 0) return 0;
        return self.a_pow_tab[self.modS(self.aLog(a) + self.n - self.aLog(b))];
    }

    fn gfInv(self: *const BchControl, a: u32) u32 {
        return self.a_pow_tab[self.n - self.aLog(a)];
    }

    // ---------------------------------------------------------------------
    // Encoding
    // ---------------------------------------------------------------------

    /// Convert packed ECC bytes into the internal zero-padded word buffer.
    fn loadEcc8(self: *BchControl, src: []const u8) void {
        self.loadEcc8To(self.ecc_buf, src);
    }

    /// Convert the internal word buffer back into packed ECC bytes.
    fn storeEcc8(self: *BchControl, dst: []u8) void {
        std.debug.assert(dst.len >= self.ecc_bytes);
        const nwords = self.eccWords() - 1;
        var i: u32 = 0;
        while (i < nwords) : (i += 1) {
            std.mem.writeInt(u32, dst[4 * i ..][0..4], self.ecc_buf[i], .big);
        }
        var pad: [4]u8 = @splat(0);
        std.mem.writeInt(u32, &pad, self.ecc_buf[nwords], .big);
        const rem = self.ecc_bytes - 4 * nwords;
        @memcpy(dst[4 * nwords ..][0..rem], pad[0..rem]);
    }

    /// Process one byte at a time (used for data not aligned to 32 bits).
    fn encodeUnaligned(self: *BchControl, data: []const u8) void {
        const stride = self.eccWords();
        const l = stride - 1;
        const tab = self.mod8_tab[0 .. 256 * stride];

        for (data) |byte| {
            const idx = @as(usize, ((self.ecc_buf[0] >> 24) ^ byte) & 0xff) * stride;
            var i: u32 = 0;
            while (i < l) : (i += 1) {
                self.ecc_buf[i] = (self.ecc_buf[i] << 8 | self.ecc_buf[i + 1] >> 24) ^
                    tab[idx + i];
            }
            self.ecc_buf[l] = (self.ecc_buf[l] << 8) ^ tab[idx + l];
        }
    }

    /// Compute or update the ECC parity of data.
    ///
    /// ecc_out is both the initial parity (allowing incremental encoding)
    /// and the output buffer. Pass a zeroed buffer for a fresh calculation.
    pub fn encode(self: *BchControl, data: []const u8, ecc_out: []u8) void {
        std.debug.assert(ecc_out.len >= self.ecc_bytes);
        self.loadEcc8(ecc_out);
        self.accumulate(data);
        self.storeEcc8(ecc_out);
    }

    /// Compute the parity of data from a zero initial state.
    fn encodeInto(self: *BchControl, data: []const u8) void {
        @memset(self.ecc_buf[0..self.eccWords()], 0);
        self.accumulate(data);
    }

    /// Fold data into the parity currently held in ecc_buf.
    fn accumulate(self: *BchControl, data: []const u8) void {
        const stride = self.eccWords();
        const l = stride - 1;

        const tab0 = self.mod8_tab[0 .. 256 * stride];
        const tab1 = self.mod8_tab[256 * stride ..][0 .. 256 * stride];
        const tab2 = self.mod8_tab[512 * stride ..][0 .. 256 * stride];
        const tab3 = self.mod8_tab[768 * stride ..][0 .. 256 * stride];
        const r = self.ecc_buf[0..stride];

        var pos: usize = 0;
        while (pos + 4 <= data.len) : (pos += 4) {
            const word = std.mem.readInt(u32, data[pos..][0..4], .big);
            const w = r[0] ^ word;
            const idx0 = @as(usize, w & 0xff) * stride;
            const idx1 = @as(usize, (w >> 8) & 0xff) * stride;
            const idx2 = @as(usize, (w >> 16) & 0xff) * stride;
            const idx3 = @as(usize, (w >> 24) & 0xff) * stride;

            var i: u32 = 0;
            while (i < l) : (i += 1) {
                r[i] = r[i + 1] ^ tab0[idx0 + i] ^ tab1[idx1 + i] ^ tab2[idx2 + i] ^ tab3[idx3 + i];
            }
            r[l] = tab0[idx0 + l] ^ tab1[idx1 + l] ^ tab2[idx2 + l] ^ tab3[idx3 + l];
        }
        if (pos < data.len) self.encodeUnaligned(data[pos..]);
    }

    /// Compute parity over bits packed one per byte (LSB is the data bit).
    pub fn encodeBits(self: *BchControl, data: []const u8, ecc_out: []u8) void {
        std.debug.assert(data.len >= self.dataBits());
        std.debug.assert(ecc_out.len >= self.eccBits());

        const nbytes = self.packDataBuf(data);
        const ecc_bytes = self.packEccRegion();
        @memset(ecc_bytes, 0);
        self.encode(self.databuf[0..nbytes], ecc_bytes);
        self.unpackEccBits(ecc_out);
    }

    // ---------------------------------------------------------------------
    // Bit-packed helpers
    // ---------------------------------------------------------------------

    fn packDataBuf(self: *BchControl, data: []const u8) usize {
        const k = self.dataBits();
        const ndatabytes = self.dataBytes();
        const pad = ndatabytes * 8 - k;
        const bytes = self.databuf[0..ndatabytes];
        @memset(bytes, 0);

        var bit: usize = 0;
        while (bit < k) : (bit += 1) {
            if ((data[bit] & 1) != 0) {
                const i = bit + pad;
                bytes[i >> 3] |= @as(u8, 1) << @intCast(7 - (i & 7));
            }
        }
        return ndatabytes;
    }

    fn packEccRegion(self: *BchControl) []u8 {
        const offset = self.dataBytes();
        return self.databuf[offset..][0..self.ecc_bytes];
    }

    fn unpackEccBits(self: *BchControl, ecc: []u8) void {
        const raw = self.packEccRegion();
        var k: usize = 0;
        while (k < self.eccBits()) : (k += 1) {
            ecc[k] = @intFromBool((raw[k >> 3] & (@as(u8, 1) << @intCast(7 - (k & 7)))) != 0);
        }
    }

    fn packEccBits(self: *BchControl, ecc: []const u8) void {
        const raw = self.packEccRegion();
        @memset(raw, 0);
        var k: usize = 0;
        while (k < self.eccBits()) : (k += 1) {
            if ((ecc[k] & 1) != 0) {
                raw[k >> 3] |= @as(u8, 1) << @intCast(7 - (k & 7));
            }
        }
    }

    /// Decode a bit-packed codeword.
    ///
    /// Returns the number of errors and writes their data-bit positions to
    /// errloc. ECC-only errors are reported with positions beyond the data
    /// bits, matching the byte-oriented decoder.
    pub fn decodeBits(
        self: *BchControl,
        data: []const u8,
        recv_ecc: []const u8,
        errloc: []u32,
    ) DecodeError!usize {
        std.debug.assert(data.len >= self.dataBits());
        std.debug.assert(recv_ecc.len >= self.eccBits());

        const nbytes = self.packDataBuf(data);
        self.packEccBits(recv_ecc);
        const ecc_bytes = self.databuf[nbytes..][0..self.eccBytes()];
        const nerr = try self.decode(self.databuf[0..nbytes], ecc_bytes, errloc);
        if (nerr > 0) {
            const pad = self.dataBytes() * 8 - self.dataBits();
            var i: usize = 0;
            while (i < nerr) : (i += 1) {
                const loc = errloc[i];
                errloc[i] = ((loc & ~@as(u32, 7)) | (7 - (loc & 7))) -% @as(u32, @intCast(pad));
            }
        }
        return nerr;
    }

    // ---------------------------------------------------------------------
    // Decoding
    // ---------------------------------------------------------------------

    /// Decode a codeword block.
    ///
    /// data and recv_ecc are the received bytes. On success the number of
    /// bit errors is returned (zero for an intact block) and their positions
    /// are written to errloc, which must have room for at least t entries.
    /// Positions below data.len * 8 refer to data bits; larger positions
    /// refer to parity bits and need no data correction.
    pub fn decode(
        self: *BchControl,
        data: []const u8,
        recv_ecc: []const u8,
        errloc: []u32,
    ) DecodeError!usize {
        if (data.len > self.dataBytes()) return error.InvalidParameters;
        if (recv_ecc.len < self.ecc_bytes) return error.InvalidParameters;
        if (errloc.len < self.t) return error.InvalidParameters;

        // Compute the parity of the received data and XOR it with the
        // received parity. If the result is zero, the block is intact.
        self.encodeInto(data);
        self.loadEcc8To(self.ecc_buf2, recv_ecc);
        var sum: u32 = 0;
        const words = self.eccWords();
        var i: u32 = 0;
        while (i < words) : (i += 1) {
            self.ecc_buf[i] ^= self.ecc_buf2[i];
            sum |= self.ecc_buf[i];
        }
        if (sum == 0) return 0;

        self.computeSyndromes();
        return self.finishDecode(self.syn, data.len, errloc);
    }

    fn loadEcc8To(self: *BchControl, dst: []u32, src: []const u8) void {
        std.debug.assert(src.len >= self.ecc_bytes);
        const nwords = self.eccWords() - 1;
        var i: u32 = 0;
        while (i < nwords) : (i += 1) {
            dst[i] = std.mem.readInt(u32, src[4 * i ..][0..4], .big);
        }
        var pad: [4]u8 = @splat(0);
        const rem = self.ecc_bytes - 4 * nwords;
        @memcpy(pad[0..rem], src[4 * nwords ..][0..rem]);
        dst[nwords] = std.mem.readInt(u32, &pad, .big);
    }

    fn finishDecode(
        self: *BchControl,
        syn: []const u32,
        len: usize,
        errloc: []u32,
    ) DecodeError!usize {
        const err = try self.computeErrorLocator(syn);
        if (err > 0) {
            const nroots = self.findPolyRoots(1, &self.elp, errloc);
            if (nroots != @as(u32, @intCast(err))) return error.Uncorrectable;
        }
        if (err > 0) {
            const nbits: u32 = @intCast(len * 8 + self.ecc_bits);
            var i: usize = 0;
            while (i < err) : (i += 1) {
                if (errloc[i] >= nbits) return error.Uncorrectable;
                errloc[i] = nbits - 1 - errloc[i];
                errloc[i] = (errloc[i] & ~@as(u32, 7)) |
                    (7 - (errloc[i] & 7));
            }
        }
        return err;
    }

    /// Flip the packed-data bits listed in errloc.
    ///
    /// Positions that fall in the parity area, or outside data, are ignored.
    pub fn correct(self: *BchControl, data: []u8, errloc: []const u32) void {
        _ = self;
        for (errloc) |bi| {
            const byte = bi >> 3;
            if (byte < data.len) {
                data[byte] ^= @as(u8, 1) << @intCast(bi & 7);
            }
        }
    }

    /// Flip the one-bit-per-byte data bits listed in errloc.
    pub fn correctBits(self: *BchControl, data: []u8, errloc: []const u32) void {
        const k = self.dataBits();
        for (errloc) |bi| {
            if (bi < k and bi < data.len) data[bi] ^= 1;
        }
    }

    /// Compute the 2t syndromes of the internal ECC buffer.
    fn computeSyndromes(self: *BchControl) void {
        const t = self.t;
        var s: i32 = @intCast(self.ecc_bits);
        const mask_bits: u32 = self.ecc_bits & 31;
        if (mask_bits != 0) {
            self.ecc_buf[self.ecc_bits / 32] &= ~((@as(u32, 1) << @intCast(32 - mask_bits)) - 1);
        }
        @memset(self.syn[0 .. 2 * t], 0);

        var word: usize = 0;
        while (true) {
            var poly = self.ecc_buf[word];
            word += 1;
            s -= 32;
            while (poly != 0) {
                const i = polyDegree(poly);
                var j: u32 = 0;
                while (j < 2 * t) : (j += 2) {
                    const exp = @as(i64, j + 1) * @as(i64, @as(i32, i) + s);
                    self.syn[j] ^= self.aPow(@intCast(exp));
                }
                poly ^= @as(u32, 1) << i;
            }
            if (s <= 0) break;
        }

        var j: u32 = 0;
        while (j < t) : (j += 1) {
            self.syn[2 * j + 1] = self.gfSqr(self.syn[j]);
        }
    }

    /// Berlekamp-Massey error locator polynomial.
    fn computeErrorLocator(self: *BchControl, syn: []const u32) DecodeError!usize {
        const t = self.t;
        const n = self.n;
        const elp = &self.elp;
        const pelp = &self.poly_2t[0];
        const elp_copy = &self.poly_2t[1];

        pelp.clear();
        elp.clear();
        pelp.c[0] = 1;
        elp.c[0] = 1;

        var i: u32 = 0;
        var d: u32 = syn[0];
        var pd: u32 = 1;
        var pp: i32 = -1;

        while (i < t and elp.deg <= t) : (i += 1) {
            if (d != 0) {
                const k: u32 = @intCast(@as(i32, @intCast(2 * i)) - pp);
                elp_copy.copyFrom(elp);
                var tmp = self.aLog(d) + n - self.aLog(pd);
                var j: u32 = 0;
                while (j <= pelp.deg) : (j += 1) {
                    if (pelp.c[j] != 0) {
                        const l = self.aLog(pelp.c[j]);
                        elp.c[j + k] ^= self.aPow(tmp + l);
                    }
                }
                tmp = pelp.deg + k;
                if (tmp > elp.deg) {
                    elp.deg = tmp;
                    pelp.copyFrom(elp_copy);
                    pd = d;
                    pp = @intCast(2 * i);
                }
            }
            if (i < t - 1) {
                d = syn[2 * i + 2];
                var j: u32 = 1;
                while (j <= elp.deg) : (j += 1) {
                    d ^= self.gfMul(elp.c[j], syn[2 * i + 2 - j]);
                }
            }
        }

        if (elp.deg > t) return error.Uncorrectable;
        return @intCast(elp.deg);
    }

    // ---------------------------------------------------------------------
    // Polynomial root finding (Berlekamp trace algorithm)
    // ---------------------------------------------------------------------

    fn polyLogRep(self: *BchControl, a: *const Poly, rep: []i32) void {
        const d = a.deg;
        const l = self.n - self.aLog(a.c[a.deg]);
        var i: u32 = 0;
        while (i < d) : (i += 1) {
            rep[i] = if (a.c[i] != 0)
                @intCast(self.modS(self.aLog(a.c[i]) + l))
            else
                -1;
        }
    }

    fn polyMod(self: *BchControl, a: *Poly, b: *const Poly, rep_in: ?[]i32) void {
        if (a.deg < b.deg) return;
        const d = b.deg;

        // The remainder modulo a non-zero constant is zero.
        if (d == 0) {
            a.deg = 0;
            a.c[0] = 0;
            return;
        }

        const rep = if (rep_in) |r| r else blk: {
            self.polyLogRep(b, self.cache);
            break :blk self.cache;
        };

        var j = a.deg;
        while (true) {
            if (a.c[j] != 0) {
                const la = self.aLog(a.c[j]);
                var p: u32 = j - d;
                var i: u32 = 0;
                while (i < d) : ({
                    i += 1;
                    p += 1;
                }) {
                    const m = rep[i];
                    if (m >= 0) {
                        a.c[p] ^= self.a_pow_tab[self.modS(@as(u32, @intCast(m)) + la)];
                    }
                }
            }
            if (j == d) break;
            j -= 1;
        }

        a.deg = d - 1;
        a.trim();
    }

    fn polyDiv(self: *BchControl, a: *Poly, b: *const Poly, q: *Poly) void {
        if (a.deg >= b.deg) {
            const qdeg = a.deg - b.deg;
            q.deg = qdeg;
            if (b.deg == 0) {
                // Dividing by a constant leaves the quotient coefficients
                // equal to the dividend. The reference implementation also
                // does not scale them; only the root set matters here.
                @memcpy(q.c[0 .. qdeg + 1], a.c[0 .. qdeg + 1]);
                a.deg = 0;
                a.c[0] = 0;
                return;
            }
            self.polyMod(a, b, null);
            @memcpy(q.c[0 .. qdeg + 1], a.c[b.deg..][0 .. qdeg + 1]);
        } else {
            q.deg = 0;
            q.c[0] = 0;
        }
    }

    fn polyGcd(self: *BchControl, a_in: *Poly, b_in: *Poly) *Poly {
        var a = a_in;
        var b = b_in;
        if (a.deg < b.deg) {
            const tmp = a;
            a = b;
            b = tmp;
        }
        while (b.deg > 0) {
            self.polyMod(a, b, null);
            const tmp = a;
            a = b;
            b = tmp;
        }
        return a;
    }

    fn computeTraceBkMod(
        self: *BchControl,
        k: u32,
        f: *const Poly,
        z: *Poly,
        out: *Poly,
    ) void {
        const m = self.m;
        z.deg = 1;
        z.c[0] = 0;
        z.c[1] = self.a_pow_tab[k];
        out.deg = 0;
        @memset(out.c[0 .. f.deg + 1], 0);

        self.polyLogRep(f, self.cache);

        var i: u32 = 0;
        while (i < m) : (i += 1) {
            var j: i32 = @intCast(z.deg);
            while (j >= 0) : (j -= 1) {
                const ju: u32 = @intCast(j);
                out.c[ju] ^= z.c[ju];
                z.c[2 * ju] = self.gfSqr(z.c[ju]);
                z.c[2 * ju + 1] = 0;
            }
            if (z.deg > out.deg) out.deg = z.deg;

            if (i < m - 1) {
                z.deg *= 2;
                self.polyMod(z, f, self.cache);
            }
        }
        out.trim();
    }

    /// Split f into g and h using the Berlekamp trace algorithm.
    ///
    /// The two output polynomials are views into f.c: g uses the low
    /// coefficients and h starts at coefficient 3 * deg(g). The gap is
    /// proportional to deg(g), so recursive splits of g (whose degrees are
    /// smaller) always stay below h. This mirrors the in-place split of the
    /// C implementation but without pointer punning.
    fn factorPolynomial(self: *BchControl, k: u32, f: *Poly, g: *Poly, h: *Poly) bool {
        const f2 = &self.poly_2t[0];
        const q = &self.poly_2t[1];
        const tk = &self.poly_2t[2];
        const z = &self.poly_2t[3];

        self.computeTraceBkMod(k, f, z, tk);
        if (tk.deg == 0) return false;

        f2.copyFrom(f);
        const gcd = self.polyGcd(f2, tk);
        if (gcd.deg >= f.deg) return false;

        self.polyDiv(f, gcd, q);

        const dg = gcd.deg;
        const dh = q.deg;
        if (dg == 0) {
            // Constant gcd: g is 1 and h is the whole polynomial. Both views
            // share the buffer; g is never read because its degree is zero.
            g.* = .{ .c = f.c, .deg = 0 };
            h.* = .{ .c = f.c, .deg = dh };
            @memcpy(g.c[0..1], gcd.c[0..1]);
            @memcpy(h.c[0 .. dh + 1], q.c[0 .. dh + 1]);
            return true;
        }

        const h_offset = 3 * dg;
        std.debug.assert(f.c.len >= h_offset + dh + 1);

        g.* = .{ .c = f.c[0..h_offset], .deg = dg };
        @memcpy(g.c[0 .. dg + 1], gcd.c[0 .. dg + 1]);

        h.* = .{ .c = f.c[h_offset..], .deg = dh };
        @memcpy(h.c[0 .. dh + 1], q.c[0 .. dh + 1]);
        return true;
    }

    fn findPolyRoots(self: *BchControl, k: u32, poly: *Poly, roots: []u32) u32 {
        switch (poly.deg) {
            1 => return self.findPolyDeg1Roots(poly, roots),
            2 => return self.findPolyDeg2Roots(poly, roots),
            3 => return self.findPolyDeg3Roots(poly, roots),
            4 => return self.findPolyDeg4Roots(poly, roots),
            else => {},
        }

        if (poly.deg == 0 or k > self.m) return 0;

        var g: Poly = undefined;
        var h: Poly = undefined;
        if (!self.factorPolynomial(k, poly, &g, &h)) {
            return self.findPolyRoots(k + 1, poly, roots);
        }

        const n1 = self.findPolyRoots(k + 1, &g, roots);
        const n2 = self.findPolyRoots(k + 1, &h, roots[n1..]);
        return n1 + n2;
    }

    fn findPolyDeg1Roots(self: *BchControl, poly: *const Poly, roots: []u32) u32 {
        if (poly.c[0] == 0) return 0;
        roots[0] = self.modS(self.n - self.aLog(poly.c[0]) + self.aLog(poly.c[1]));
        return 1;
    }

    fn findPolyDeg2Roots(self: *BchControl, poly: *const Poly, roots: []u32) u32 {
        if (poly.c[0] == 0 or poly.c[1] == 0) return 0;

        const l0 = self.aLog(poly.c[0]);
        const l1 = self.aLog(poly.c[1]);
        const l2 = self.aLog(poly.c[2]);
        const u = self.aPow(l0 + l2 + 2 * (self.n - l1));

        var r: u32 = 0;
        var v = u;
        while (v != 0) {
            const i = polyDegree(v);
            r ^= self.xi_tab[i];
            v ^= @as(u32, 1) << i;
        }

        if ((self.gfSqr(r) ^ r) != u) return 0;
        roots[0] = self.modulo(2 * self.n - l1 - self.aLog(r) + l2);
        roots[1] = self.modulo(2 * self.n - l1 - self.aLog(r ^ 1) + l2);
        return 2;
    }

    fn findPolyDeg3Roots(self: *BchControl, poly: *const Poly, roots: []u32) u32 {
        if (poly.c[0] == 0) return 0;

        const e3 = poly.c[3];
        const c2 = self.gfDiv(poly.c[0], e3);
        const b2 = self.gfDiv(poly.c[1], e3);
        const a2 = self.gfDiv(poly.c[2], e3);
        const c = self.gfMul(a2, c2);
        const b = self.gfMul(a2, b2) ^ c2;
        const a = self.gfSqr(a2) ^ b2;

        var tmp: [4]u32 = undefined;
        if (self.findAffine4Roots(a, b, c, &tmp) != 4) return 0;

        var n: u32 = 0;
        for (tmp) |v| {
            if (v != a2) {
                roots[n] = self.aIlog(v);
                n += 1;
            }
        }
        return n;
    }

    fn findPolyDeg4Roots(self: *BchControl, poly: *const Poly, roots: []u32) u32 {
        if (poly.c[0] == 0) return 0;

        const e4 = poly.c[4];
        var d = self.gfDiv(poly.c[0], e4);
        const c = self.gfDiv(poly.c[1], e4);
        var b = self.gfDiv(poly.c[2], e4);
        const a = self.gfDiv(poly.c[3], e4);
        var e: u32 = 0;

        if (a != 0) {
            if (c != 0) {
                const f = self.gfDiv(c, a);
                var l: u32 = self.aLog(f);
                if ((l & 1) != 0) l += self.n;
                e = self.aPow(l / 2);
                d = self.aPow(2 * l) ^ self.gfMul(b, f) ^ d;
                b = self.gfMul(a, e) ^ b;
            }
            if (d == 0) return 0;
            const c2 = self.gfInv(d);
            const b2 = self.gfDiv(a, d);
            const a2 = self.gfDiv(b, d);
            return self.finishDeg4(a, a2, b2, c2, e, roots);
        }

        return self.finishDeg4(a, b, c, d, e, roots);
    }

    fn finishDeg4(
        self: *BchControl,
        a: u32,
        a2: u32,
        b2: u32,
        c2: u32,
        e: u32,
        roots: []u32,
    ) u32 {
        if (self.findAffine4Roots(a2, b2, c2, roots) != 4) return 0;
        for (roots[0..4]) |*r| {
            const f = if (a != 0) self.gfInv(r.*) else r.*;
            r.* = self.aIlog(f ^ e);
        }
        return 4;
    }

    fn findAffine4Roots(self: *BchControl, a: u32, b: u32, c: u32, roots: []u32) i32 {
        const m = self.m;
        var mask: u32 = 0xff;
        var rows: [16]u32 = @splat(0);

        var j = self.aLog(b);
        var k = self.aLog(a);
        rows[0] = c;

        var i: u32 = 0;
        while (i < m) : (i += 1) {
            const a_term: u32 = if (a != 0) self.a_pow_tab[self.modS(k)] else 0;
            const b_term: u32 = if (b != 0) self.a_pow_tab[self.modS(j)] else 0;
            rows[i + 1] = self.a_pow_tab[4 * i] ^ a_term ^ b_term;
            j += 1;
            k += 2;
        }

        var shift: u32 = 8;
        while (shift != 0) : ({
            shift >>= 1;
            mask ^= mask << @intCast(shift);
        }) {
            var idx: u32 = 0;
            while (idx < 16) : (idx = (idx + shift + 1) & ~shift) {
                const t = ((rows[idx] >> @intCast(shift)) ^ rows[idx + shift]) & mask;
                rows[idx] ^= t << @intCast(shift);
                rows[idx + shift] ^= t;
            }
        }

        return self.solveLinearSystem(&rows, roots, 4);
    }

    fn solveLinearSystem(
        self: *BchControl,
        rows: []u32,
        sol: []u32,
        nsol: i32,
    ) i32 {
        const m: i32 = @intCast(self.m);
        var param: [max_m]i32 = undefined;

        var k: i32 = 0;
        var mask: u32 = @as(u32, 1) << @intCast(m);

        var c: i32 = 0;
        while (c < m) : (c += 1) {
            var rem: i32 = 0;
            const p = c - k;

            var r = p;
            while (r < m) : (r += 1) {
                const ru: usize = @intCast(r);
                if ((rows[ru] & mask) != 0) {
                    if (r != p) {
                        const pu: usize = @intCast(p);
                        const tmp = rows[ru];
                        rows[ru] = rows[pu];
                        rows[pu] = tmp;
                    }
                    rem = r + 1;
                    break;
                }
            }

            if (rem != 0) {
                const pu: usize = @intCast(p);
                const tmp = rows[pu];
                var rr = rem;
                while (rr < m) : (rr += 1) {
                    const ru: usize = @intCast(rr);
                    if ((rows[ru] & mask) != 0) rows[ru] ^= tmp;
                }
            } else {
                param[@intCast(k)] = c;
                k += 1;
            }
            mask >>= 1;
        }

        if (k > 0) {
            var p = k;
            var r = m - 1;
            while (r >= 0) : (r -= 1) {
                const ru: usize = @intCast(r);
                if (r > m - 1 - k and rows[ru] != 0) return 0;
                if (p != 0 and r == param[@intCast(p - 1)]) {
                    p -= 1;
                    rows[ru] = @as(u32, 1) << @intCast(m - r);
                } else {
                    rows[ru] = rows[@intCast(r - p)];
                }
            }
        }

        if (nsol != @as(i32, 1) << @intCast(k)) return 0;

        var p: i32 = 0;
        while (p < nsol) : (p += 1) {
            var cc: i32 = 0;
            while (cc < k) : (cc += 1) {
                const idx: usize = @intCast(param[@intCast(cc)]);
                rows[idx] = (rows[idx] & ~@as(u32, 1)) | @as(u32, @intCast((p >> @intCast(cc)) & 1));
            }

            var tmp: u32 = 0;
            var r = m - 1;
            while (r >= 0) : (r -= 1) {
                const mask2 = rows[@intCast(r)] & (tmp | 1);
                tmp |= bitParity(mask2) << @intCast(m - r);
            }
            sol[@intCast(p)] = tmp >> 1;
        }
        return nsol;
    }

    // ---------------------------------------------------------------------
    // Initialisation
    // ---------------------------------------------------------------------

    fn buildGfTables(self: *BchControl, poly: u32) !void {
        const k = @as(u32, 1) << polyDegree(poly);
        if (k != @as(u32, 1) << @intCast(self.m)) return error.InvalidPrimitivePolynomial;

        var x: u32 = 1;
        var i: u32 = 0;
        while (i < self.n) : (i += 1) {
            self.a_pow_tab[i] = @truncate(x);
            self.a_log_tab[x] = @truncate(i);
            if (i != 0 and x == 1) return error.InvalidPrimitivePolynomial;
            x <<= 1;
            if ((x & k) != 0) x ^= poly;
        }
        self.a_pow_tab[self.n] = 1;
        self.a_log_tab[0] = 0;
    }

    fn computeGeneratorPolynomial(self: *BchControl) ![]u32 {
        const allocator = self.arena.allocator();
        const mt = self.m * self.t;

        var g = Poly.init(try allocator.alloc(u32, mt + 1));
        const roots = try allocator.alloc(u32, self.n + 1);
        @memset(roots, 0);

        var i: u32 = 0;
        while (i < self.t) : (i += 1) {
            var r = 2 * i + 1;
            var j: u32 = 0;
            while (j < self.m) : (j += 1) {
                roots[r] = 1;
                r = self.modS(2 * r);
            }
        }

        g.deg = 0;
        g.c[0] = 1;
        i = 0;
        while (i < self.n) : (i += 1) {
            if (roots[i] != 0) {
                const rpow = self.a_pow_tab[i];
                g.c[g.deg + 1] = 1;
                var j = g.deg;
                while (j > 0) : (j -= 1) {
                    g.c[j] = self.gfMul(g.c[j], rpow) ^ g.c[j - 1];
                }
                g.c[0] = self.gfMul(g.c[0], rpow);
                g.deg += 1;
            }
        }

        self.ecc_bits = g.deg;
        const words = divRoundUp(mt + 1, 32);
        const genpoly = try allocator.alloc(u32, words);

        var n: i32 = @intCast(g.deg + 1);
        var widx: u32 = 0;
        while (n > 0) {
            const nbits: u32 = if (n > 32) 32 else @intCast(n);
            var word: u32 = 0;
            var j: u32 = 0;
            while (j < nbits) : (j += 1) {
                if (g.c[@intCast(n - 1 - @as(i32, @intCast(j)))] != 0) {
                    word |= @as(u32, 1) << @intCast(31 - j);
                }
            }
            genpoly[widx] = word;
            widx += 1;
            n -= @intCast(nbits);
        }
        return genpoly;
    }

    fn buildMod8Tables(self: *BchControl, genpoly: []const u32) void {
        const stride = self.eccWords();
        const plen = divRoundUp(self.ecc_bits + 1, 32);
        const ecclen = divRoundUp(self.ecc_bits, 32);
        @memset(self.mod8_tab, 0);

        var i: u32 = 0;
        while (i < 256) : (i += 1) {
            var b: u32 = 0;
            while (b < 4) : (b += 1) {
                const tab = self.mod8_tab[(b * 256 + i) * stride ..][0..stride];
                var data: u32 = i << @intCast(8 * b);
                while (data != 0) {
                    const d = polyDegree(data);
                    data ^= genpoly[0] >> (31 - d);
                    var j: u32 = 0;
                    while (j < ecclen) : (j += 1) {
                        const hi: u32 = if (d < 31) genpoly[j] << @intCast(d + 1) else 0;
                        const lo: u32 = if (j + 1 < plen) genpoly[j + 1] >> (31 - d) else 0;
                        tab[j] ^= hi | lo;
                    }
                }
            }
        }
    }

    fn buildDeg2Base(self: *BchControl) !void {
        const m = self.m;
        var xi: [max_m]u32 = @splat(0);
        var ak: u32 = 0;
        var found = false;

        var i: u32 = 0;
        while (i < m) : (i += 1) {
            var sum: u32 = 0;
            var j: u32 = 0;
            while (j < m) : (j += 1) {
                sum ^= self.aPow(i * (@as(u32, 1) << @intCast(j)));
            }
            if (sum != 0) {
                ak = self.a_pow_tab[i];
                found = true;
                break;
            }
        }
        if (!found) return error.Degree2BaseNotFound;

        var remaining = m;
        var x: u32 = 0;
        while (x <= self.n and remaining != 0) : (x += 1) {
            var y = self.gfSqr(x) ^ x;
            var attempt: u32 = 0;
            while (attempt < 2) : (attempt += 1) {
                if (y != 0) {
                    const r = self.aLog(y);
                    if (r < m and xi[r] == 0) {
                        self.xi_tab[r] = x;
                        xi[r] = 1;
                        remaining -= 1;
                        break;
                    }
                }
                y ^= ak;
            }
        }
        if (remaining != 0) return error.Degree2BaseNotFound;
    }

    fn elpCapacity(t: u32) u32 {
        // Berlekamp-Massey needs at most 2t coefficients. The in-place BTA
        // split places the second factor at coefficient 3*deg(g), so 3t+1
        // coefficients are enough; keep a little slack.
        return 3 * t + 4;
    }

    /// Initialise a BCH codec for GF(2^m).
    ///
    /// t is the maximum number of correctable bit errors. Pass zero for
    /// prim_poly to use the default primitive polynomial for m.
    pub fn init(m: u32, t: u32, prim_poly_in: u32) !*BchControl {
        if (m < min_m or m > max_m) return error.InvalidParameters;
        // Bound t before multiplying so that m * t cannot overflow and
        // so that the generator polynomial has at most n distinct roots.
        const n = (@as(u32, 1) << @intCast(m)) - 1;
        if (t < 1 or t > (n - 1) / m) return error.InvalidParameters;

        const prim_poly = if (prim_poly_in == 0)
            default_prim_polys[m - min_m]
        else
            prim_poly_in;

        const page_allocator = std.heap.page_allocator;
        const bch = try page_allocator.create(BchControl);
        errdefer page_allocator.destroy(bch);

        bch.arena = std.heap.ArenaAllocator.init(page_allocator);
        errdefer bch.arena.deinit();

        const allocator = bch.arena.allocator();
        const words = divRoundUp(m * t, 32);

        bch.m = m;
        bch.n = n;
        bch.t = t;
        bch.ecc_bits = 0;
        bch.ecc_bytes = divRoundUp(m * t, 8);

        bch.a_pow_tab = try allocator.alloc(u16, n + 1);
        bch.a_log_tab = try allocator.alloc(u16, n + 1);
        bch.mod8_tab = try allocator.alloc(u32, 1024 * words);
        bch.ecc_buf = try allocator.alloc(u32, words);
        bch.ecc_buf2 = try allocator.alloc(u32, words);
        bch.xi_tab = try allocator.alloc(u32, m);
        bch.syn = try allocator.alloc(u32, 2 * t);
        bch.cache = try allocator.alloc(i32, 2 * t);

        bch.elp = Poly.init(try allocator.alloc(u32, elpCapacity(t)));
        for (&bch.poly_2t) |*p| {
            p.* = Poly.init(try allocator.alloc(u32, 2 * t + 2));
        }

        try bch.buildGfTables(prim_poly);
        const genpoly = try bch.computeGeneratorPolynomial();
        bch.buildMod8Tables(genpoly);
        try bch.buildDeg2Base();

        bch.databuf = try allocator.alloc(u8, divRoundUp(n - bch.ecc_bits, 8) + bch.ecc_bytes);
        return bch;
    }

    pub fn deinit(self: *BchControl) void {
        const page_allocator = std.heap.page_allocator;
        self.arena.deinit();
        page_allocator.destroy(self);
    }
};
