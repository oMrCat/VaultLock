using FolderLock.Core.Integration;

namespace FolderLock.Core.Tests.Integration;

public sealed class ShellMenuSpecTests
{
    private const string Exe = @"C:\Program Files\VaultLock\FolderLock.App.exe";

    [Fact]
    public void ForDirectory_BuildsTwoFlatEntries()
    {
        var definitions = ShellMenuSpec.ForDirectory(Exe, "zh");

        Assert.Equal(2, definitions.Count);
        Assert.Equal(@"Directory\shell\VaultLock.Lock", definitions[0].KeyPath);
        Assert.Equal(@"Directory\shell\VaultLock.Unlock", definitions[1].KeyPath);
        Assert.All(definitions, definition => Assert.Equal(Exe, definition.Icon));
        Assert.Equal("VaultLock：加锁", definitions[0].DisplayName);
        Assert.Equal("VaultLock：解锁", definitions[1].DisplayName);
    }

    [Fact]
    public void ForDirectory_EachEntryIsFlatSingleCommand()
    {
        var definitions = ShellMenuSpec.ForDirectory(Exe, "zh");

        // 平铺项必须恰好一条命令（WriteDefinition 据此走平铺写法）
        Assert.All(definitions, definition => Assert.Single(definition.Commands));
        Assert.Equal("--lock \"%1\"", definitions[0].Commands[0].Arguments);
        Assert.Equal("--unlock \"%1\"", definitions[1].Commands[0].Arguments);
        Assert.All(
            definitions.SelectMany(definition => definition.Commands),
            command => Assert.Equal("Player", ShellMenuSpec.MultiSelectModel));
    }

    [Fact]
    public void ForVaultFile_BuildsSingleFlatOpenEntry()
    {
        var definitions = ShellMenuSpec.ForVaultFile(Exe, "zh");

        var definition = Assert.Single(definitions);
        Assert.Equal(@"SystemFileAssociations\.flvault\shell\VaultLock.Open", definition.KeyPath);
        Assert.Single(definition.Commands);
        Assert.Equal("--open \"%1\"", definition.Commands[0].Arguments);
    }

    [Fact]
    public void EnglishLabels_AreLocalized()
    {
        var directory = ShellMenuSpec.ForDirectory(Exe, "en");
        var vault = ShellMenuSpec.ForVaultFile(Exe, "en");

        Assert.Equal("VaultLock：Lock", directory[0].DisplayName);
        Assert.Equal("Lock", directory[0].Commands[0].Label);
        Assert.Equal("VaultLock：Open in VaultLock", vault[0].DisplayName);
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
    public void LegacyKeyPaths_CoverOldCascadeAndOldFlatVerbs()
    {
        // 旧级联父键必须进清理列表，否则老用户注册表会残留重复菜单
        Assert.Contains(@"Directory\shell\VaultLock", ShellMenuSpec.LegacyKeyPaths);
        Assert.Contains(@"SystemFileAssociations\.flvault\shell\VaultLock", ShellMenuSpec.LegacyKeyPaths);
        Assert.Contains(@"Directory\shell\FolderLock.Add", ShellMenuSpec.LegacyKeyPaths);
        Assert.Contains(@"Directory\shell\FolderLock.Lock", ShellMenuSpec.LegacyKeyPaths);
        Assert.Contains(@"Directory\shell\FolderLock.Unlock", ShellMenuSpec.LegacyKeyPaths);
    }
}
