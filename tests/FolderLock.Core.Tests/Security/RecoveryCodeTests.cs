using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public class RecoveryCodeTests
{
    [Fact]
    public void Generate_ProducesFormattedCode()
    {
        var code = RecoveryCode.Generate();

        Assert.Equal(32, RecoveryCode.Normalize(code).Length);
        Assert.Contains('-', code);
    }

    [Fact]
    public void Generate_IsUnique()
    {
        Assert.NotEqual(RecoveryCode.Generate(), RecoveryCode.Generate());
    }

    [Theory]
    [InlineData("abcd-efgh", "ABCDEFGH")]
    [InlineData("il0o", "1100")]
    [InlineData("A B C", "ABC")]
    public void Normalize_MapsAmbiguousCharactersAndSeparators(string input, string expected)
    {
        Assert.Equal(expected, RecoveryCode.Normalize(input));
    }
}
