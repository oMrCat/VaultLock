using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class ServiceSignaturePolicyTests : IDisposable
{
    private readonly string? _originalValue = Environment.GetEnvironmentVariable(
        ServiceSignaturePolicy.RequireEnvironmentVariable);

    private readonly string _settingsPath =
        Path.Combine(Path.GetTempPath(), $"folderlock-service-settings-{Guid.NewGuid():N}.json");

    [Fact]
    public void DefaultsToWarningModeWhenNothingIsConfigured()
    {
        Environment.SetEnvironmentVariable(ServiceSignaturePolicy.RequireEnvironmentVariable, null);

        Assert.False(ServiceSignaturePolicy.IsRequired(_settingsPath));
        Assert.Equal(SignatureEnforcementMode.Warn, ServiceSignaturePolicy.CurrentMode);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData("yes")]
    [InlineData("on")]
    public void EnvironmentVariableEnablesStrictMode(string value)
    {
        Environment.SetEnvironmentVariable(ServiceSignaturePolicy.RequireEnvironmentVariable, value);

        Assert.True(ServiceSignaturePolicy.IsRequired(_settingsPath));
    }

    [Fact]
    public void EnvironmentVariableCanDisableConfigurationFile()
    {
        File.WriteAllText(_settingsPath, """{ "requireServiceSignature": true }""");
        Environment.SetEnvironmentVariable(ServiceSignaturePolicy.RequireEnvironmentVariable, "0");

        Assert.False(ServiceSignaturePolicy.IsRequired(_settingsPath));
    }

    [Fact]
    public void SettingsFileEnablesStrictMode()
    {
        Environment.SetEnvironmentVariable(ServiceSignaturePolicy.RequireEnvironmentVariable, null);
        File.WriteAllText(_settingsPath, """{ "RequireServiceSignature": true }""");

        Assert.True(ServiceSignaturePolicy.IsRequired(_settingsPath));
    }

    [Fact]
    public void InvalidSettingsFileFallsBackToWarningMode()
    {
        Environment.SetEnvironmentVariable(ServiceSignaturePolicy.RequireEnvironmentVariable, null);
        File.WriteAllText(_settingsPath, "{ not json");

        Assert.False(ServiceSignaturePolicy.IsRequired(_settingsPath));
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(ServiceSignaturePolicy.RequireEnvironmentVariable, _originalValue);

        try
        {
            File.Delete(_settingsPath);
        }
        catch
        {
        }
    }
}
