const std = @import("std");
const Bch = @import("bch.zig");

const page_size = std.heap.page_size_min;

extern fn SHA256(data: [*]const u8, len: usize, digest: [*]u8) [*]u8;

fn sha256(data: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    // OpenSSL requires a valid pointer even for a zero-length input.
    var empty: [1]u8 = .{0};
    const ptr = if (data.len == 0) &empty else data.ptr;
    _ = SHA256(ptr, data.len, &digest);
    return digest;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn usage() void {
    std.debug.print(
        \\Usage:
        \\  servar encode <input> [-o output] [--m M] [--t T] [--no-hash]
        \\  servar verify <input> [checksum]
        \\  servar repair <input> [checksum]
        \\  servar help
        \\
    , .{});
}

fn readU16(buf: []const u8, pos: *usize) !u16 {
    if (pos.* + 2 > buf.len) return error.Truncated;
    const v = std.mem.readInt(u16, buf[pos.*..][0..2], .little);
    pos.* += 2;
    return v;
}

fn readU32(buf: []const u8, pos: *usize) !u32 {
    if (pos.* + 4 > buf.len) return error.Truncated;
    const v = std.mem.readInt(u32, buf[pos.*..][0..4], .little);
    pos.* += 4;
    return v;
}

fn readU64(buf: []const u8, pos: *usize) !u64 {
    if (pos.* + 8 > buf.len) return error.Truncated;
    const v = std.mem.readInt(u64, buf[pos.*..][0..8], .little);
    pos.* += 8;
    return v;
}

fn initBch(m: u32, t: u32) !*Bch.BchControl {
    return Bch.BchControl.init(m, t, 0);
}

fn cmdEncode(init: std.process.Init, allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    const io = init.io;
    var input: ?[]const u8 = null;
    var output: ?[]const u8 = null;
    var m: u32 = 13;
    var t: u32 = 8;
    var no_hash: bool = false;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "-o") or eql(args[i], "--output")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            output = args[i];
        } else if (eql(args[i], "--m")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            m = try std.fmt.parseInt(u32, args[i], 10);
        } else if (eql(args[i], "--t")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            t = try std.fmt.parseInt(u32, args[i], 10);
        } else if (eql(args[i], "--no-hash")) {
            no_hash = true;
        } else {
            if (input == null) input = args[i] else return error.UnexpectedArg;
        }
    }
    const in_path = input orelse return error.MissingInput;
    const out_path = output orelse try std.fmt.allocPrint(allocator, "{s}.ser", .{in_path});
    defer if (output == null) allocator.free(out_path);

    const file = try std.Io.Dir.cwd().openFile(io, in_path, .{});
    defer file.close(io);
    const st = try file.stat(io);
    const file_size: usize = @intCast(st.size);

    const mapped = if (file_size == 0)
        @as([]align(page_size) u8, &.{})
    else
        try std.posix.mmap(null, file_size, .{ .READ = true }, .{ .TYPE = .SHARED }, file.handle, 0);
    defer if (file_size > 0) std.posix.munmap(mapped);

    const has_hash: bool = !no_hash;
    const hash = if (has_hash) sha256(mapped) else @as([32]u8, @splat(0));

    const b = try initBch(m, t);
    defer b.deinit();
    const K: usize = b.blockBytes();
    const ecc_bytes: usize = b.eccBytes();
    const total_msg: usize = file_size + (if (has_hash) @as(usize, 32) else @as(usize, 0));
    const num_blocks: usize = (total_msg + K - 1) / K;

    const parity = try allocator.alloc(u8, num_blocks * ecc_bytes);
    defer allocator.free(parity);
    @memset(parity, 0);

    const Ctx = struct {
        m: u32,
        t: u32,
        mapped: []align(page_size) u8,
        file_size: usize,
        hash: [32]u8,
        K: usize,
        ecc_bytes: usize,
        total: usize,
        parity: []u8,
        start: usize,
        end: usize,
    };
    const worker = struct {
        fn run(ctx: *Ctx) void {
            const bch = initBch(ctx.m, ctx.t) catch return;
            defer bch.deinit();
            var bi = ctx.start;
            while (bi < ctx.end) : (bi += 1) {
                const offset = bi * ctx.K;
                const block_len = @min(ctx.K, ctx.total - offset);
                const block_parity = ctx.parity[bi * ctx.ecc_bytes ..][0..ctx.ecc_bytes];
                if (offset + block_len <= ctx.file_size) {
                    bch.encode(ctx.mapped[offset..][0..block_len], block_parity);
                } else {
                    var tmp: [8192]u8 = undefined;
                    var file_part: usize = 0;
                    if (offset < ctx.file_size) file_part = ctx.file_size - offset;
                    const hash_offset = if (offset >= ctx.file_size) offset - ctx.file_size else 0;
                    const hash_count = block_len - file_part;
                    if (file_part > 0) @memcpy(tmp[0..file_part], ctx.mapped[offset..ctx.file_size]);
                    @memcpy(tmp[file_part .. file_part + hash_count], ctx.hash[hash_offset .. hash_offset + hash_count]);
                    bch.encode(tmp[0..block_len], block_parity);
                }
            }
        }
    }.run;

    const cpu = std.Thread.getCpuCount() catch 4;
    const nthreads = @min(cpu, if (num_blocks == 0) 1 else num_blocks);
    const ctxs = try allocator.alloc(Ctx, nthreads);
    defer allocator.free(ctxs);
    const threads = try allocator.alloc(std.Thread, nthreads);
    defer allocator.free(threads);

    const blocks_per = (num_blocks + nthreads - 1) / nthreads;
    var start: usize = 0;
    var ti: usize = 0;
    while (start < num_blocks) : (ti += 1) {
        const end = @min(start + blocks_per, num_blocks);
        ctxs[ti] = .{
            .m = m,
            .t = t,
            .mapped = mapped,
            .file_size = file_size,
            .hash = hash,
            .K = K,
            .ecc_bytes = ecc_bytes,
            .total = total_msg,
            .parity = parity,
            .start = start,
            .end = end,
        };
        threads[ti] = try std.Thread.spawn(.{}, worker, .{&ctxs[ti]});
        start = end;
    }
    // if num_blocks == 0, still no threads; handle
    if (num_blocks == 0) {
        // nothing
    }
    for (threads[0..ti]) |thr| thr.join();

    // write checksum file
    const out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer out_file.close(io);
    var wbuf: [64 * 1024]u8 = undefined;
    var w = out_file.writer(io, &wbuf);

    try w.interface.writeAll("SERVAR");
    try w.interface.writeInt(u16, 1, .little);
    try w.interface.writeInt(u32, m, .little);
    try w.interface.writeInt(u32, t, .little);
    try w.interface.writeInt(u32, if (has_hash) @as(u32, 1) else @as(u32, 0), .little);
    try w.interface.writeInt(u32, @intCast(K), .little);
    try w.interface.writeInt(u32, @intCast(ecc_bytes), .little);
    try w.interface.writeInt(u64, file_size, .little);
    try w.interface.writeInt(u64, num_blocks, .little);
    try w.interface.writeAll(&hash);
    const base = std.fs.path.basename(in_path);
    try w.interface.writeInt(u32, @intCast(base.len), .little);
    try w.interface.writeAll(base);
    try w.interface.writeAll(parity);
    try w.interface.flush();

    std.debug.print("Encoded {s}: size={d}, blocks={d}, m={d}, t={d}, K={d}\n", .{ in_path, file_size, num_blocks, m, t, K });
    std.debug.print("Checksum written to {s}\n", .{out_path});
}

const Cksum = struct {
    has_hash: bool,
    m: u32,
    t: u32,
    K: usize,
    ecc_bytes: usize,
    file_size: usize,
    num_blocks: usize,
    hash: [32]u8,
    parity: []const u8,
    base_name: []const u8,
};

fn parseChecksum(allocator: std.mem.Allocator, data: []const u8) !Cksum {
    var pos: usize = 0;
    if (data.len < 8) return error.BadFormat;
    if (!std.mem.eql(u8, data[0..6], "SERVAR")) return error.BadMagic;
    pos = 6;
    const version = try readU16(data, &pos);
    if (version != 1) return error.BadVersion;
    var has_hash: bool = true;
    var m: u32 = undefined;
    var t: u32 = undefined;
    var K: usize = undefined;
    var ecc_bytes: usize = undefined;
    m = try readU32(data, &pos);
    t = try readU32(data, &pos);
    has_hash = (try readU32(data, &pos)) != 0;
    K = try readU32(data, &pos);
    ecc_bytes = try readU32(data, &pos);
    const file_size: usize = @intCast(try readU64(data, &pos));
    const num_blocks: usize = @intCast(try readU64(data, &pos));
    if (pos + 32 > data.len) return error.Truncated;
    var hash: [32]u8 = undefined;
    @memcpy(&hash, data[pos .. pos + 32]);
    pos += 32;
    const name_len = try readU32(data, &pos);
    if (pos + name_len > data.len) return error.Truncated;
    const base_name = try allocator.dupe(u8, data[pos .. pos + name_len]);
    pos += name_len;
    const parity_len = num_blocks * ecc_bytes;
    if (pos + parity_len != data.len) return error.BadParityLen;
    const parity = try allocator.dupe(u8, data[pos .. pos + parity_len]);
    return .{
        .has_hash = has_hash,
        .m = m,
        .t = t,
        .K = K,
        .ecc_bytes = ecc_bytes,
        .file_size = file_size,
        .num_blocks = num_blocks,
        .hash = hash,
        .parity = parity,
        .base_name = base_name,
    };
}

fn cmdVerify(init: std.process.Init, allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    const io = init.io;
    if (args.len < 3) return error.MissingArgs;
    const in_path = args[2];
    const own_ck = args.len < 4;
    const ck_path = if (own_ck) try std.fmt.allocPrint(allocator, "{s}.ser", .{in_path}) else args[3];
    defer if (own_ck) allocator.free(ck_path);

    const ck_data = try std.Io.Dir.cwd().readFileAlloc(io, ck_path, allocator, std.Io.Limit.unlimited);
    defer allocator.free(ck_data);
    const ck = try parseChecksum(allocator, ck_data);
    defer allocator.free(ck.parity);
    defer allocator.free(ck.base_name);

    const file = try std.Io.Dir.cwd().openFile(io, in_path, .{});
    defer file.close(io);
    const st = try file.stat(io);
    const file_size: usize = @intCast(st.size);

    const mapped = if (file_size == 0)
        @as([]align(page_size) u8, &.{})
    else
        try std.posix.mmap(null, file_size, .{ .READ = true }, .{ .TYPE = .SHARED }, file.handle, 0);
    defer if (file_size > 0) std.posix.munmap(mapped);

    if (ck.has_hash) {
        const cur_hash = sha256(mapped);
        if (file_size == ck.file_size and std.mem.eql(u8, &cur_hash, &ck.hash)) {
            std.debug.print("OK: {s} matches checksum (no damage detected)\n", .{in_path});
        } else {
            std.debug.print("MISMATCH: {s} differs from checksum\n", .{in_path});
            if (file_size != ck.file_size) std.debug.print("  size: got {d}, expected {d}\n", .{ file_size, ck.file_size });
            std.debug.print("  run 'servar repair' to attempt recovery\n", .{});
        }
    } else {
        if (file_size != ck.file_size) {
            std.debug.print("MISMATCH: {s} size differs (got {d}, expected {d})\n", .{ in_path, file_size, ck.file_size });
            return;
        }
        const b = try initBch(ck.m, ck.t);
        defer b.deinit();
        var bad: usize = 0;
        var bi: usize = 0;
        const errloc = try allocator.alloc(u32, b.errorCapacity());
        defer allocator.free(errloc);
        while (bi < ck.num_blocks) : (bi += 1) {
            const offset = bi * ck.K;
            const blen = @min(ck.K, ck.file_size - offset);
            const msg = mapped[offset..][0..blen];
            const parity = ck.parity[bi * ck.ecc_bytes ..][0..ck.ecc_bytes];
            const nerr = b.decode(msg, parity, errloc) catch {
                bad += 1;
                continue;
            };
            if (nerr != 0) bad += 1;
        }
        if (bad == 0) {
            std.debug.print("OK: {s} matches checksum (no damage detected)\n", .{in_path});
        } else {
            std.debug.print("MISMATCH: {s} has {d} bad blocks\n", .{ in_path, bad });
            std.debug.print("  run 'servar repair' to attempt recovery\n", .{});
        }
    }
}

fn cmdRepair(init: std.process.Init, allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    const io = init.io;
    if (args.len < 3) return error.MissingArgs;
    const in_path = args[2];
    const own_ck = args.len < 4;
    const ck_path = if (own_ck) try std.fmt.allocPrint(allocator, "{s}.ser", .{in_path}) else args[3];
    defer if (own_ck) allocator.free(ck_path);

    const ck_data = try std.Io.Dir.cwd().readFileAlloc(io, ck_path, allocator, std.Io.Limit.unlimited);
    defer allocator.free(ck_data);
    const ck = try parseChecksum(allocator, ck_data);
    defer allocator.free(ck.parity);
    defer allocator.free(ck.base_name);

    const b = try initBch(ck.m, ck.t);
    defer b.deinit();
    // validate K
    const K: usize = b.blockBytes();
    if (K != ck.K) return error.ParamMismatch;

    const file = try std.Io.Dir.cwd().openFile(io, in_path, .{});
    defer file.close(io);
    const st = try file.stat(io);
    const file_size: usize = @intCast(st.size);
    if (file_size != ck.file_size) {
        std.debug.print("File size mismatch: got {d}, expected {d}\n", .{ file_size, ck.file_size });
        return error.SizeMismatch;
    }

    const mapped = if (file_size == 0)
        @as([]align(page_size) u8, &.{})
    else
        try std.posix.mmap(null, file_size, .{ .READ = true }, .{ .TYPE = .SHARED }, file.handle, 0);

    const total_msg = file_size + (if (ck.has_hash) @as(usize, 32) else @as(usize, 0));
    const combined = try allocator.alloc(u8, total_msg);
    defer allocator.free(combined);
    if (file_size > 0) @memcpy(combined[0..file_size], mapped);
    if (ck.has_hash) @memcpy(combined[file_size..total_msg], &ck.hash);

    const Ctx = struct {
        m: u32,
        t: u32,
        combined: []u8,
        total_msg: usize,
        K: usize,
        ecc_bytes: usize,
        parity: []const u8,
        start: usize,
        end: usize,
        total_errors: usize = 0,
        bad_blocks: usize = 0,
    };
    const worker = struct {
        fn run(ctx: *Ctx) void {
            const bch = initBch(ctx.m, ctx.t) catch return;
            defer bch.deinit();
            const errloc_buf = std.heap.page_allocator.alloc(u32, bch.errorCapacity()) catch return;
            defer std.heap.page_allocator.free(errloc_buf);
            var bi = ctx.start;
            while (bi < ctx.end) : (bi += 1) {
                const offset = bi * ctx.K;
                const block_len = @min(ctx.K, ctx.total_msg - offset);
                const msg = ctx.combined[offset..][0..block_len];
                const parity = ctx.parity[bi * ctx.ecc_bytes ..][0..ctx.ecc_bytes];
                const nerr = bch.decode(msg, parity, errloc_buf) catch |err| {
                    ctx.bad_blocks += 1;
                    std.debug.print("Block {d}: uncorrectable ({s})\n", .{ bi, @errorName(err) });
                    continue;
                };
                if (nerr > 0) {
                    bch.correct(msg, errloc_buf[0..nerr]);
                    ctx.total_errors += nerr;
                }
            }
        }
    }.run;

    const cpu = std.Thread.getCpuCount() catch 4;
    const nthreads = @min(cpu, if (ck.num_blocks == 0) 1 else ck.num_blocks);
    const ctxs = try allocator.alloc(Ctx, nthreads);
    defer allocator.free(ctxs);
    const threads = try allocator.alloc(std.Thread, nthreads);
    defer allocator.free(threads);

    const blocks_per = (ck.num_blocks + nthreads - 1) / nthreads;
    var start: usize = 0;
    var ti: usize = 0;
    while (start < ck.num_blocks) : (ti += 1) {
        const end = @min(start + blocks_per, ck.num_blocks);
        ctxs[ti] = .{
            .m = ck.m,
            .t = ck.t,
            .combined = combined,
            .total_msg = total_msg,
            .K = ck.K,
            .ecc_bytes = ck.ecc_bytes,
            .parity = ck.parity,
            .start = start,
            .end = end,
        };
        threads[ti] = try std.Thread.spawn(.{}, worker, .{&ctxs[ti]});
        start = end;
    }
    for (threads[0..ti]) |thr| thr.join();

    var total_errors: usize = 0;
    var bad_blocks: usize = 0;
    for (ctxs[0..ti]) |c| {
        total_errors += c.total_errors;
        bad_blocks += c.bad_blocks;
    }

    if (file_size > 0) std.posix.munmap(mapped);

    // write repaired file
    const out_file = try std.Io.Dir.cwd().openFile(io, in_path, .{ .mode = .write_only });
    defer out_file.close(io);
    // truncate
    try out_file.setLength(io, 0);
    var wbuf: [64 * 1024]u8 = undefined;
    var w = out_file.writer(io, &wbuf);
    try w.interface.writeAll(combined[0..file_size]);
    try w.interface.flush();

    std.debug.print("Repair done: corrected {d} bit errors in {d} blocks, {d} uncorrectable blocks\n", .{ total_errors, ck.num_blocks, bad_blocks });
    if (ck.has_hash) {
        const file2 = try std.Io.Dir.cwd().openFile(io, in_path, .{});
        defer file2.close(io);
        const st2 = try file2.stat(io);
        const sz2: usize = @intCast(st2.size);
        const mapped2 = if (sz2 == 0) @as([]align(page_size) u8, &.{}) else try std.posix.mmap(null, sz2, .{ .READ = true }, .{ .TYPE = .SHARED }, file2.handle, 0);
        defer if (sz2 > 0) std.posix.munmap(mapped2);
        const cur_hash = sha256(mapped2);
        if (std.mem.eql(u8, &cur_hash, &ck.hash)) {
            std.debug.print("OK: repaired file hash matches\n", .{});
        } else {
            std.debug.print("WARNING: repaired file hash still mismatched\n", .{});
        }
    } else {
        std.debug.print("OK: repair complete (SHA-256 disabled)\n", .{});
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        usage();
        return;
    }
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "encode")) {
        try cmdEncode(init, allocator, args);
    } else if (std.mem.eql(u8, cmd, "verify")) {
        try cmdVerify(init, allocator, args);
    } else if (std.mem.eql(u8, cmd, "repair")) {
        try cmdRepair(init, allocator, args);
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        usage();
    } else {
        usage();
        return error.UnknownCommand;
    }
}
