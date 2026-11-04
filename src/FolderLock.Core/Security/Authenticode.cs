using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FolderLock.Core.Security;

public enum AuthenticodeStatus
{
    /// <summary>签名存在且信任链验证通过。</summary>
    Valid,

    /// <summary>文件没有 Authenticode 签名。</summary>
    NotSigned,

    /// <summary>签名存在但验证失败（被篡改、证书不受信任等）。</summary>
    Invalid,

    /// <summary>无法读取文件或验证过程出错。</summary>
    Error,
}

/// <summary>基于 WinVerifyTrust 的 Authenticode 状态检查（不联网、不做吊销检查）。</summary>
public static class Authenticode
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;

    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEUnknownSubject = unchecked((int)0x800B0004);

    private static readonly Guid ActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static AuthenticodeStatus GetStatus(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return AuthenticodeStatus.Error;
        }

        IntPtr fileInfoPtr = IntPtr.Zero;
        IntPtr dataPtr = IntPtr.Zero;
        try
        {
            var fileInfo = new WinTrustFileInfo
            {
                CbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = Path.GetFullPath(path),
            };

            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WinTrustData
            {
                CbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                File = fileInfoPtr,
                StateAction = WtdStateActionVerify,
            };

            dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(data, dataPtr, false);

            var result = WinVerifyTrust(IntPtr.Zero, ActionGenericVerifyV2, dataPtr);

            // 关闭验证状态，释放 wintrust 内部资源。
            data.StateAction = WtdStateActionClose;
            Marshal.StructureToPtr(data, dataPtr, false);
            WinVerifyTrust(IntPtr.Zero, ActionGenericVerifyV2, dataPtr);

            return result switch
            {
                0 => AuthenticodeStatus.Valid,
                TrustENoSignature or TrustESubjectFormUnknown or TrustEUnknownSubject => AuthenticodeStatus.NotSigned,
                _ => AuthenticodeStatus.Invalid,
            };
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or CryptographicException)
        {
            return AuthenticodeStatus.Error;
        }
        catch
        {
            return AuthenticodeStatus.Error;
        }
        finally
        {
            if (dataPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(dataPtr);
            }

            if (fileInfoPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPtr);
            }
        }
    }

    /// <summary>
    /// 读取嵌入签名中的签名者证书主题；未签名或读取失败时返回 null。
    /// 仅在 <see cref="GetStatus"/> 返回 <see cref="AuthenticodeStatus.Valid"/> 后使用才有意义。
    /// </summary>
    public static string? GetSignerSubject(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(path);
            return certificate.Subject;
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (SystemException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint CbStruct;
        public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint CbStruct;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr File;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        IntPtr actionData);
}
