using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using FolderLock.Core.Security;

namespace VaultProbe;

internal static class Program
{
    private const string Password = "P@ssw0rd-测试密码";
    private const int BaseHeaderSize = 164;
    private const int V2HeaderSize = 196;

    private static readonly string Root = Path.Combine(Path.GetTempPath(), "VaultProbe-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
    private static readonly VaultEncryptor Vault = new();

    private static int _passed;
    private static int _failed;

    private static string? _filter;

    private static void Main(string[] args)
    {
        _filter = Environment.GetEnvironmentVariable("VAULT_PROBE_FILTER");
        Directory.CreateDirectory(Root);
        Console.WriteLine("VaultProbe 运行目录: " + Root);
        Console.WriteLine();

        Run("01 加解密往返（未压缩，含空文件/空目录/中文与 emoji 路径）", RoundtripPlain);
        Run("02 加解密往返（压缩）", RoundtripCompressed);
        Run("03 错误密码必须失败且不留下明文", WrongPassword);
        Run("04 篡改数据块密文必须失败", TamperCiphertext);
        Run("05 篡改头部 flags 必须失败", TamperHeaderFlags);
        Run("06 篡改 KDF 迭代次数（超大值）必须立即拒绝", TamperIterationsHuge);
        Run("07 篡改 KDF 迭代次数（正常范围）必须失败", TamperIterationsNormal);
        Run("08 截断（去掉结束块）必须失败", TruncateTrailer);
        Run("09 截断（只保留首个数据块）必须失败", TruncateMiddle);
        Run("10 篡改结束块标签必须失败", TamperTrailerTag);
        Run("11 v1 旧格式容器仍可解密（向后兼容）", LegacyV1Readable);
        Run("12 每次加密/每块 nonce 均不重复", NonceUniqueness);
        Run("13 大文件流式处理（128MB）", LargeFileStreaming);
        Run("14 并发加密/解密", Concurrency);
        Run("15 加密中途取消：不生成容器、不残留 tmp", CancellationDuringEncrypt);
        Run("16 路径穿越片段必须被拒绝", PathTraversalRejected);
        Run("17 已存在容器默认拒绝覆盖", OverwriteRefused);
        Run("18 损坏/过短的容器 TryVerify 返回 false 而非抛出", TryVerifyRobust);
        Run("19 空目录往返", EmptyDirectory);
        Run("20 恢复码可用、错误恢复码不可用", RecoveryCodeFlow);
        Run("21 目录联接未加密时必须出现在报告的跳过清单里", SymlinkSkippedReported);

        Console.WriteLine();
        Console.WriteLine($"RESULT: passed={_passed} failed={_failed}");
        Console.WriteLine("（运行目录可删除：" + Root + "）");
        Environment.ExitCode = _failed == 0 ? 0 : 1;
    }

    // ---------------------------------------------------------------- 用例

    private static void RoundtripPlain()
    {
        var src = Dir("01-src");
        PopulateSample(src);

        var vault = Path.Combine(Dir("01-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, "RECOVERY-CODE", compress: false, overwrite: true);
        var info = Vault.ReadHeaderInfo(vault);
        Assert("01a 头部版本=2", info.Version == 2, $"version={info.Version}");
        Assert("01b 头部记录未压缩", !info.IsCompressed, "IsCompressed=true");

        var target = Path.Combine(Dir("01-restored"), "tree");
        Vault.DecryptToDirectory(vault, target, Password);
        var diff = CompareTrees(src, target);
        Assert("01c 目录树与文件内容一致", diff is null, diff ?? "");
    }

    private static void RoundtripCompressed()
    {
        var src = Dir("02-src");
        PopulateSample(src);

        var vault = Path.Combine(Dir("02-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: true, overwrite: true);
        Assert("02a 头部记录已压缩", Vault.ReadHeaderInfo(vault).IsCompressed, "IsCompressed=false");

        var target = Path.Combine(Dir("02-restored"), "tree");
        Vault.DecryptToDirectory(vault, target, Password);
        var diff = CompareTrees(src, target);
        Assert("02b 压缩容器内容一致", diff is null, diff ?? "");
    }

    private static void WrongPassword()
    {
        var src = Dir("03-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("03-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);

        var target = Path.Combine(Dir("03-restored"), "tree");
        var threw = false;
        try
        {
            Vault.DecryptToDirectory(vault, target, "wrong-password");
        }
        catch (VaultException)
        {
            threw = true;
        }

        Assert("03a 错误密码抛出 VaultException", threw, "未抛出 VaultException");
        Assert("03b 错误密码未写出明文", CountFiles(target) == 0, "目标目录出现文件");
        Assert("03c 错误密码后容器仍然完好", Vault.TryVerify(vault, Password), "正确密码反而校验失败");
    }

    private static void TamperCiphertext()
    {
        var src = Dir("04-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("04-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);

        var bytes = File.ReadAllBytes(vault);
        Assert("04a 容器足够长", bytes.Length > V2HeaderSize + 20, "容器过短");
        bytes[V2HeaderSize + 4 + 12] ^= 0x01; // 第一个数据块的密文首字节
        var tampered = WriteCopy("04-out", "tampered.flvault", bytes);

        Assert("04b 篡改密文校验失败", !Vault.TryVerify(tampered, Password), "篡改后依然通过校验");
        var threw = false;
        try
        {
            Vault.DecryptToDirectory(tampered, Path.Combine(Dir("04-restored"), "tree"), Password);
        }
        catch (VaultException)
        {
            threw = true;
        }

        Assert("04c 篡改密文解密抛出 VaultException", threw, "未抛出");
    }

    private static void TamperHeaderFlags()
    {
        var src = Dir("05-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("05-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);

        var bytes = File.ReadAllBytes(vault);
        bytes[7] ^= 0x02; // 翻转 compressed 标志
        var tampered = WriteCopy("05-out", "flags.flvault", bytes);

        var threw = false;
        string message = "";
        try
        {
            Vault.Verify(tampered, Password);
        }
        catch (VaultException ex)
        {
            threw = true;
            message = ex.Message;
        }

        Assert("05a 篡改头部 flags 抛出 VaultException", threw, "未抛出");
        Assert("05b 错误信息指向头部校验", message.Contains("头部"), message);
    }

    private static void TamperIterationsHuge()
    {
        var src = Dir("06-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("06-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);

        var bytes = File.ReadAllBytes(vault);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), 60_000_000);
        var tampered = WriteCopy("06-out", "iters.flvault", bytes);

        var started = Stopwatch.StartNew();
        var threw = false;
        try
        {
            Vault.Verify(tampered, Password);
        }
        catch (VaultException)
        {
            threw = true;
        }

        started.Stop();
        Assert("06a 超大迭代次数被拒绝", threw, "未抛出");
        Assert("06b 拒绝耗时 < 1s（无 KDF 放大）", started.ElapsedMilliseconds < 1000, $"耗时 {started.ElapsedMilliseconds}ms");
    }

    private static void TamperIterationsNormal()
    {
        var src = Dir("07-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("07-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);

        var bytes = File.ReadAllBytes(vault);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), 1_000_000);
        var tampered = WriteCopy("07-out", "iters.flvault", bytes);

        var threw = false;
        try
        {
            Vault.Verify(tampered, Password);
        }
        catch (VaultException)
        {
            threw = true;
        }

        Assert("07a 篡改迭代次数后无法解包密钥", threw, "未抛出");
    }

    private static void TruncateTrailer()
    {
        var src = Dir("08-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("08-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);

        var bytes = File.ReadAllBytes(vault);
        var truncated = WriteCopy("08-out", "no-trailer.flvault", bytes.Take(bytes.Length - 48).ToArray());

        var threw = false;
        try
        {
            Vault.Verify(truncated, Password);
        }
        catch (VaultException)
        {
            threw = true;
        }

        Assert("08a 去掉结束块后校验失败（旧实现会静默通过）", threw, "未抛出");
        Assert("08b TryVerify 返回 false", !Vault.TryVerify(truncated, Password), "TryVerify=true");
    }

    private static void TruncateMiddle()
    {
        var big = Dir("09-src");
        var payload = RandomBytes(200 * 1024);
        File.WriteAllBytes(Path.Combine(big, "big.bin"), payload);

        var vault = Path.Combine(Dir("09-out"), "vault.flvault");
        Vault.EncryptDirectory(big, vault, Password, null, compress: false, overwrite: true);

        var bytes = File.ReadAllBytes(vault);
        var firstChunkEnd = V2HeaderSize + 4 + 12 + 65536 + 16;
        Assert("09a 容器含多个数据块", bytes.Length > firstChunkEnd, $"len={bytes.Length}");
        var truncated = WriteCopy("09-out", "one-chunk.flvault", bytes.Take(firstChunkEnd).ToArray());

        var threw = false;
        try
        {
            Vault.Verify(truncated, Password);
        }
        catch (VaultException)
        {
            threw = true;
        }

        Assert("09b 只保留首块后校验失败", threw, "未抛出");
    }

    private static void TamperTrailerTag()
    {
        var src = Dir("10-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("10-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);

        var bytes = File.ReadAllBytes(vault);
        bytes[^1] ^= 0x01;
        var tampered = WriteCopy("10-out", "trailer.flvault", bytes);

        var threw = false;
        try
        {
            Vault.Verify(tampered, Password);
        }
        catch (VaultException)
        {
            threw = true;
        }

        Assert("10a 结束块标签被篡改时校验失败", threw, "未抛出");
    }

    private static void LegacyV1Readable()
    {
        var dir = Dir("11-out");
        var vault = Path.Combine(dir, "legacy-v1.flvault");
        var content = Encoding.UTF8.GetBytes("legacy payload 旧格式内容");
        const string legacyRecovery = "ABCD-EFGH-JKMN-PQRS";
        WriteLegacyV1(vault, Password, legacyRecovery, "legacy/旧文件.txt", content);

        var info = Vault.ReadHeaderInfo(vault);
        Assert("11a v1 头部可识别", info.Version == 1, $"version={info.Version}");
        Assert("11b v1 头部记录含恢复码", info.HasRecovery, "HasRecovery=false");

        var target = Path.Combine(Dir("11-restored"), "tree");
        Vault.DecryptToDirectory(vault, target, Password);
        var restored = Path.Combine(target, "legacy", "旧文件.txt");
        Assert("11c v1 内容解密正确", File.Exists(restored) &&
            File.ReadAllBytes(restored).SequenceEqual(content), "内容不一致");

        var recoveryTarget = Path.Combine(Dir("11-restored"), "by-recovery");
        Vault.DecryptToDirectory(vault, recoveryTarget, legacyRecovery);
        var restoredByCode = Path.Combine(recoveryTarget, "legacy", "旧文件.txt");
        Assert("11d v1 容器可用恢复码解密", File.Exists(restoredByCode) &&
            File.ReadAllBytes(restoredByCode).SequenceEqual(content), "内容不一致");
    }

    private static void NonceUniqueness()
    {
        var src = Dir("12-src");
        File.WriteAllBytes(Path.Combine(src, "big.bin"), RandomBytes(2 * 1024 * 1024));

        var a = Path.Combine(Dir("12-out"), "a.flvault");
        var b = Path.Combine(Dir("12-out"), "b.flvault");
        Vault.EncryptDirectory(src, a, Password, null, compress: false, overwrite: true);
        Vault.EncryptDirectory(src, b, Password, null, compress: false, overwrite: true);

        var noncesA = ReadNonces(a);
        var noncesB = ReadNonces(b);
        Assert("12a 单容器内 nonce 数量 > 30", noncesA.Count > 30, $"count={noncesA.Count}");
        Assert("12b 单容器内 nonce 无重复", noncesA.Distinct(StringComparer.Ordinal).Count() == noncesA.Count, "出现重复 nonce");
        Assert("12c 两次加密的 nonce 集合不同", !noncesA.Intersect(noncesB, StringComparer.Ordinal).Any(), "两次加密复用了 nonce");
    }

    private static void LargeFileStreaming()
    {
        var src = Dir("13-src");
        var path = Path.Combine(src, "large.bin");
        const long size = 128L * 1024 * 1024;
        using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        {
            var buffer = new byte[1024 * 1024];
            long written = 0;
            while (written < size)
            {
                var take = (int)Math.Min(buffer.Length, size - written);
                RandomNumberGenerator.Fill(buffer.AsSpan(0, take));
                fs.Write(buffer, 0, take);
                written += take;
            }
        }

        var srcHash = Sha256(path);
        var vault = Path.Combine(Dir("13-out"), "large.flvault");
        var target = Path.Combine(Dir("13-restored"), "tree");

        var before = Process.GetCurrentProcess().PeakWorkingSet64;
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);
        Vault.DecryptToDirectory(vault, target, Password);
        var after = Process.GetCurrentProcess().PeakWorkingSet64;

        var restored = Path.Combine(target, "large.bin");
        Assert("13a 128MB 内容往返一致", Sha256(restored) == srcHash, "哈希不一致");
        var deltaMb = (after - before) / (1024.0 * 1024.0);
        Assert("13b 峰值内存增量 < 200MB（流式处理）", deltaMb < 200, $"增量 {deltaMb:0.0}MB");

        TryDeleteDir(src);
        TryDeleteDir(target);
        File.Delete(vault);
    }

    private static void Concurrency()
    {
        var src = Dir("14-src");
        PopulateSample(src);
        File.WriteAllBytes(Path.Combine(src, "bulk.bin"), RandomBytes(5 * 1024 * 1024));

        var outDir = Dir("14-out");
        var vaults = Enumerable.Range(0, 4).Select(i => Path.Combine(outDir, $"v{i}.flvault")).ToArray();

        var errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        Parallel.For(0, 4, i =>
        {
            try
            {
                Vault.EncryptDirectory(src, vaults[i], Password, null, compress: i % 2 == 1, overwrite: true);
            }
            catch (Exception ex)
            {
                errors.Add($"encrypt[{i}] {ex.GetType().Name}: {ex.Message}");
            }
        });

        Assert("14a 4 路并发加密全部成功", errors.IsEmpty, string.Join(" | ", errors));

        var decryptErrors = new System.Collections.Concurrent.ConcurrentBag<string>();
        Parallel.For(0, 4, i =>
        {
            try
            {
                var target = Path.Combine(Dir("14-restored"), "t" + i);
                Vault.DecryptToDirectory(vaults[i], target, Password);
                var diff = CompareTrees(src, target);
                if (diff is not null)
                {
                    decryptErrors.Add($"decrypt[{i}] {diff}");
                }
            }
            catch (Exception ex)
            {
                decryptErrors.Add($"decrypt[{i}] {ex.GetType().Name}: {ex.Message}");
            }
        });

        Assert("14b 4 路并发解密内容一致", decryptErrors.IsEmpty, string.Join(" | ", decryptErrors));
    }

    private static void CancellationDuringEncrypt()
    {
        var src = Dir("15-src");
        File.WriteAllBytes(Path.Combine(src, "big.bin"), RandomBytes(30 * 1024 * 1024));
        var outDir = Dir("15-out");
        var vault = Path.Combine(outDir, "cancelled.flvault");

        using var cts = new CancellationTokenSource();
        var progress = new CancelingProgress(cts, 20);

        var threw = false;
        try
        {
            Vault.EncryptDirectory(src, vault, Password, null, progress: progress, cancellationToken: cts.Token, compress: false);
        }
        catch (OperationCanceledException)
        {
            threw = true;
        }

        Assert("15a 取消时抛出 OperationCanceledException", threw, "未抛出");
        Assert("15b 取消后没有生成容器", !File.Exists(vault), "容器存在");
        Assert("15c 取消后没有残留 tmp", Directory.GetFiles(outDir, "*.tmp").Length == 0, "存在 tmp 文件");
        Assert("15d 取消后源文件完好", new FileInfo(Path.Combine(src, "big.bin")).Length == 30L * 1024 * 1024, "源文件被改动");
        TryDeleteDir(src);
    }

    private static void PathTraversalRejected()
    {
        var target = Dir("16-target");
        var method = typeof(VaultEncryptor).GetMethod("ResolveTarget", BindingFlags.NonPublic | BindingFlags.Static)
                     ?? throw new MissingMethodException("ResolveTarget");

        string[] attacks =
        {
            @"sub/..\..\escape.txt",
            @"..\..\escape.txt",
            "sub/../../escape.txt",
            "C:/escape.txt",
            "/escape.txt",
        };

        var escaped = new List<string>();
        foreach (var rel in attacks)
        {
            try
            {
                method.Invoke(null, new object?[] { target, rel });
                escaped.Add(rel);
            }
            catch (TargetInvocationException)
            {
            }
        }

        Assert("16a 非法路径片段全部被拒绝", escaped.Count == 0, "未拒绝: " + string.Join(", ", escaped));

        var normal = method.Invoke(null, new object?[] { target, "a/b.txt" }) as string;
        Assert("16b 合法相对路径仍可用", normal is not null &&
            normal.StartsWith(Path.TrimEndingDirectorySeparator(target) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase),
            normal ?? "null");
    }

    private static void OverwriteRefused()
    {
        var src = Dir("17-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("17-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);
        var originalLength = new FileInfo(vault).Length;

        var threw = false;
        try
        {
            Vault.EncryptDirectory(src, vault, Password, null, compress: false);
        }
        catch (VaultException)
        {
            threw = true;
        }

        Assert("17a 默认拒绝覆盖已存在容器", threw, "未抛出");
        Assert("17b 原容器未被改动", new FileInfo(vault).Length == originalLength &&
            Vault.TryVerify(vault, Password), "容器被改写");
    }

    private static void TryVerifyRobust()
    {
        var dir = Dir("18-out");
        var junk = Path.Combine(dir, "junk.flvault");
        File.WriteAllBytes(junk, RandomBytes(100));

        var result = false;
        Exception? unexpected = null;
        try
        {
            result = Vault.TryVerify(junk, Password);
        }
        catch (Exception ex)
        {
            unexpected = ex;
        }

        Assert("18a 过短文件 TryVerify 返回 false", unexpected is null && !result,
            unexpected is null ? "返回 true" : unexpected.GetType().Name + ": " + unexpected.Message);

        var empty = Path.Combine(dir, "empty.flvault");
        File.WriteAllBytes(empty, Array.Empty<byte>());
        Assert("18b 空文件 TryVerify 返回 false", !Vault.TryVerify(empty, Password), "返回 true");
    }

    private static void EmptyDirectory()
    {
        var src = Dir("19-src");
        var vault = Path.Combine(Dir("19-out"), "vault.flvault");
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true);
        var target = Path.Combine(Dir("19-restored"), "tree");
        Vault.DecryptToDirectory(vault, target, Password);
        Assert("19a 空目录往返成功", Directory.Exists(target) && CountFiles(target) == 0, "目标不存在或有文件");
    }

    private static void RecoveryCodeFlow()
    {
        var src = Dir("20-src");
        PopulateSample(src);
        var vault = Path.Combine(Dir("20-out"), "vault.flvault");
        var code = "ABCD-EFGH-JKMN-PQRS";
        Vault.EncryptDirectory(src, vault, Password, code, compress: false, overwrite: true);

        var target = Path.Combine(Dir("20-restored"), "tree");
        Vault.DecryptToDirectory(vault, target, code);
        var diff = CompareTrees(src, target);
        Assert("20a 恢复码可解密", diff is null, diff ?? "");

        var bad = false;
        try
        {
            Vault.DecryptToDirectory(vault, Path.Combine(Dir("20-restored"), "bad"), "WRONG-CODE");
        }
        catch (VaultException)
        {
            bad = true;
        }

        Assert("20b 错误恢复码失败", bad, "未抛出");
    }

    private static void SymlinkSkippedReported()
    {
        var src = Dir("21-src");
        File.WriteAllText(Path.Combine(src, "data.txt"), "hello");
        var outside = Dir("21-outside");
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "outside-secret");

        var link = Path.Combine(src, "linked");
        var exit = RunCommand($"mklink /J \"{link}\" \"{outside}\"");
        Assert("21a 目录联接创建成功（前置条件）", exit == 0 && Directory.Exists(link), $"exit={exit}");
        if (exit != 0)
        {
            return;
        }

        var vault = Path.Combine(Dir("21-out"), "vault.flvault");
        var report = new VaultEncryptionReport();
        Vault.EncryptDirectory(src, vault, Password, null, compress: false, overwrite: true, report: report);
        Assert(
            "21b 报告包含未加密的联接点",
            report.SkippedEntries.Count == 1 && report.SkippedEntries[0].Contains("linked"),
            "skipped=" + string.Join("|", report.SkippedEntries));

        var target = Path.Combine(Dir("21-restored"), "tree");
        Vault.DecryptToDirectory(vault, target, Password);
        Assert(
            "21c 联接点目标内容未进入容器",
            !File.Exists(Path.Combine(target, "linked", "secret.txt")),
            "容器里出现了联接目标内容");
        Assert("21d 普通文件正常进入容器", File.Exists(Path.Combine(target, "data.txt")), "普通文件缺失");
    }

    // ---------------------------------------------------------------- 辅助

    private sealed class CancelingProgress : IProgress<VaultProgress>
    {
        private readonly CancellationTokenSource _cts;
        private readonly double _threshold;

        public CancelingProgress(CancellationTokenSource cts, double threshold)
        {
            _cts = cts;
            _threshold = threshold;
        }

        public void Report(VaultProgress value)
        {
            if (value.Percent >= _threshold)
            {
                _cts.Cancel();
            }
        }
    }

    private static void Run(string name, Action test)
    {
        if (_filter is not null && !name.Contains(_filter, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            test();
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine($"[FAIL] {name} -> 未预期异常 {ex.GetType().Name}: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
    }

    private static void Assert(string name, bool condition, string detail)
    {
        if (condition)
        {
            _passed++;
            Console.WriteLine($"[PASS] {name}");
        }
        else
        {
            _failed++;
            Console.WriteLine($"[FAIL] {name} -> {detail}");
        }
    }

    private static string Dir(string name)
    {
        var path = Path.Combine(Root, name);
        Directory.CreateDirectory(path);
        return path;
    }

    private static int RunCommand(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c " + arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
        });

        if (process is null)
        {
            return -1;
        }

        process.WaitForExit();
        return process.ExitCode;
    }

    private static void PopulateSample(string dir)
    {
        File.WriteAllBytes(Path.Combine(dir, "empty.dat"), Array.Empty<byte>());
        File.WriteAllText(Path.Combine(dir, "one.txt"), "A");
        File.WriteAllBytes(Path.Combine(dir, "small.bin"), RandomBytes(1024));

        var unicodeDir = Path.Combine(dir, "中文目录");
        Directory.CreateDirectory(unicodeDir);
        File.WriteAllText(Path.Combine(unicodeDir, "表情😀.txt"), "unicode content");

        var nested = Path.Combine(dir, "a", "b");
        Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(nested, "deep.txt"), "deep");

        Directory.CreateDirectory(Path.Combine(dir, "empty-sub"));

        var stamp = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
        {
            File.SetLastWriteTimeUtc(file, stamp);
        }
    }

    private static string? CompareTrees(string expectedRoot, string actualRoot)
    {
        if (!Directory.Exists(actualRoot))
        {
            return "目标目录不存在";
        }

        var expectedFiles = RelativeFiles(expectedRoot);
        var actualFiles = RelativeFiles(actualRoot);

        foreach (var rel in expectedFiles.Except(actualFiles, StringComparer.OrdinalIgnoreCase))
        {
            return "缺少文件 " + rel;
        }

        foreach (var rel in actualFiles.Except(expectedFiles, StringComparer.OrdinalIgnoreCase))
        {
            return "多出文件 " + rel;
        }

        foreach (var rel in expectedFiles)
        {
            var a = Path.Combine(expectedRoot, rel);
            var b = Path.Combine(actualRoot, rel);
            if (Sha256(a) != Sha256(b))
            {
                return "内容不一致 " + rel;
            }
        }

        var expectedDirs = RelativeDirs(expectedRoot);
        var actualDirs = RelativeDirs(actualRoot);
        foreach (var rel in expectedDirs.Except(actualDirs, StringComparer.OrdinalIgnoreCase))
        {
            return "缺少目录 " + rel;
        }

        return null;
    }

    private static List<string> RelativeFiles(string root) =>
        Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(root, f))
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static List<string> RelativeDirs(string root) =>
        Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
            .Select(d => Path.GetRelativePath(root, d))
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static int CountFiles(string root) =>
        Directory.Exists(root) ? Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Count() : 0;

    private static string Sha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    private static string WriteCopy(string dir, string name, byte[] bytes)
    {
        var path = Path.Combine(Dir(dir), name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static List<string> ReadNonces(string vaultPath)
    {
        var result = new List<string>();
        var bytes = File.ReadAllBytes(vaultPath);
        var pos = V2HeaderSize;
        while (pos + 4 <= bytes.Length)
        {
            var length = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(pos, 4));
            pos += 4;
            if (length < 0)
            {
                break;
            }

            var nonce = Convert.ToHexString(bytes.AsSpan(pos, 12));
            result.Add(nonce);
            pos += 12 + length + 16;
        }

        return result;
    }

    private static void TryDeleteDir(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
        }
    }

    /// <summary>按旧版（v1）格式写一个容器，用于验证向后兼容。</summary>
    private static void WriteLegacyV1(string vaultPath, string password, string recoveryCode, string fileName, byte[] content)
    {
        var iterations = PasswordHasher.DefaultIterations;
        var dek = RandomNumberGenerator.GetBytes(32);
        var saltPassword = RandomNumberGenerator.GetBytes(16);
        var saltRecovery = RandomNumberGenerator.GetBytes(16);
        var kek = Rfc2898DeriveBytes.Pbkdf2(password, saltPassword, iterations, HashAlgorithmName.SHA256, 32);
        var wrappedPassword = WrapLegacy(kek, dek);
        var kekRecovery = Rfc2898DeriveBytes.Pbkdf2(
            RecoveryCode.Normalize(recoveryCode), saltRecovery, iterations, HashAlgorithmName.SHA256, 32);
        var wrappedRecovery = WrapLegacy(kekRecovery, dek);

        var header = new byte[BaseHeaderSize];
        Encoding.ASCII.GetBytes("FLVLT1").CopyTo(header, 0);
        header[6] = 1;
        header[7] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8, 4), iterations);
        saltPassword.CopyTo(header, 12);
        saltRecovery.CopyTo(header, 28);
        wrappedPassword.CopyTo(header, 44);
        wrappedRecovery.CopyTo(header, 44 + wrappedPassword.Length);

        using var output = new FileStream(vaultPath, FileMode.Create, FileAccess.Write);
        output.Write(header);

        var payloadStream = new MemoryStream();
        using (var binary = new BinaryWriter(payloadStream, Encoding.UTF8, leaveOpen: true))
        {
            binary.Write(1);
            binary.Write((byte)0);
            var name = Encoding.UTF8.GetBytes(fileName);
            binary.Write(name.Length);
            binary.Write(name);
            binary.Write(DateTime.UtcNow.Ticks);
            binary.Write((long)content.Length);
            binary.Write(content);
        }

        var payload = payloadStream.ToArray();
        using var gcm = new AesGcm(dek, 16);
        long index = 0;
        for (var offset = 0; offset < payload.Length; offset += 65536, index++)
        {
            var length = Math.Min(65536, payload.Length - offset);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[length];
            var tag = new byte[16];
            var aad = new byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(aad, index);
            gcm.Encrypt(nonce, payload.AsSpan(offset, length), ciphertext, tag, aad);

            var lengthBytes = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, length);
            output.Write(lengthBytes);
            output.Write(nonce);
            output.Write(ciphertext);
            output.Write(tag);
        }

        Span<byte> end = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(end, 0);
        output.Write(end);
    }

    private static byte[] WrapLegacy(byte[] kek, byte[] dek)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[dek.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(kek, 16);
        gcm.Encrypt(nonce, dek, ciphertext, tag);

        var result = new byte[12 + 32 + 16];
        nonce.CopyTo(result, 0);
        ciphertext.CopyTo(result, 12);
        tag.CopyTo(result, 44);
        return result;
    }
}
