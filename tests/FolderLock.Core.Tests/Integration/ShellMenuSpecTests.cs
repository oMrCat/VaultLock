using FolderLock.Core.Integration;

namespace FolderLock.Core.Tests.Integration;

public sealed class ShellMenuSpecTests
{
    private const string Exe = @"C:\Program Files\VaultLock\FolderLock.App.exe";

    [Fact]
    public void ForDirectory_BuildsCascadeWithExpectedCommands()
    {
        var definition = ShellMenuSpec.ForDirectory(Exe, "zh");

        Assert.Equal(@"Directory\shell\VaultLock", definition.KeyPath);
        Assert.Equal("VaultLock", definition.DisplayName);
        Assert.Equal(Exe, definition.Icon);
        Assert.Equal(
            new[] { "01lock", "02unlock", "03add", "04remove", "05open" },
            definition.Commands.Select(command => command.KeyName).ToArray());
        Assert.Equal(
            new[] { "加锁", "解锁", "加入保护列表", "移出保护列表", "在 VaultLock 中打开" },
            definition.Commands.Select(command => command.Label).ToArray());
    }

    [Fact]
    public void ForDirectory_ArgumentsUsePercentOneAndVerb()
    {
        var definition = ShellMenuSpec.ForDirectory(Exe, "zh");

        Assert.Equal("--lock \"%1\"", definition.Commands[0].Arguments);
        Assert.Equal("--unlock \"%1\"", definition.Commands[1].Arguments);
        Assert.Equal("--add \"%1\"", definition.Commands[2].Arguments);
        Assert.Equal("--remove \"%1\"", definition.Commands[3].Arguments);
        Assert.Equal("--open \"%1\"", definition.Commands[4].Arguments);
    }

    [Fact]
    public void ForVaultFile_BuildsVerifyDecryptSalvageOpen()
    {
        var definition = ShellMenuSpec.ForVaultFile(Exe, "zh");

        Assert.Equal(@"SystemFileAssociations\.flvault\shell\VaultLock", definition.KeyPath);
        Assert.Equal(
            new[] { "01verify", "02decrypt", "03salvage", "04open" },
            definition.Commands.Select(command => command.KeyName).ToArray());
        Assert.Equal(
            new[] { "验证容器", "解密到文件夹", "抢救容器", "在 VaultLock 中打开" },
            definition.Commands.Select(command => command.Label).ToArray());
    }

    [Fact]
    public void EnglishLabels_AreLocalized()
    {
        var directory = ShellMenuSpec.ForDirectory(Exe, "en");
        var vault = ShellMenuSpec.ForVaultFile(Exe, "en");

        Assert.Equal("Lock", directory.Commands[0].Label);
        Assert.Equal("Remove from protection list", directory.Commands[3].Label);
        Assert.Equal("Verify vault", vault.Commands[0].Label);
        Assert.Equal("Salvage vault", vault.Commands[2].Label);
    }

    [Fact]
    public void ClassesRoot_ReflectsScope()
    {
        Assert.Equal(@"HKEY_CURRENT_USER\Software\Classes", ShellMenuSpec.ClassesRoot(ShellMenuScope.CurrentUser));
        Assert.Equal(@"HKEY_LOCAL_MACHINE\Software\Classes", ShellMenuSpec.ClassesRoot(ShellMenuScope.LocalMachine));
    }

    [Fact]
    public void MultiSelectModel_IsPlayer()
    {
        Assert.Equal("Player", ShellMenuSpec.MultiSelectModel);
    }

    [Fact]
    public void LegacyKeyPaths_CoverOldFlatVerbs()
    {
        Assert.Equal(3, ShellMenuSpec.LegacyKeyPaths.Count);
        Assert.Contains(@"Directory\shell\FolderLock.Add", ShellMenuSpec.LegacyKeyPaths);
        Assert.Contains(@"Directory\shell\FolderLock.Lock", ShellMenuSpec.LegacyKeyPaths);
        Assert.Contains(@"Directory\shell\FolderLock.Unlock", ShellMenuSpec.LegacyKeyPaths);
    }
}
