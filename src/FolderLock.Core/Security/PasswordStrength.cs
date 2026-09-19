namespace FolderLock.Core.Security;

public enum PasswordStrengthLevel
{
    VeryWeak = 0,
    Weak = 1,
    Fair = 2,
    Strong = 3,
    VeryStrong = 4,
}

public static class PasswordStrength
{
    public static PasswordStrengthLevel Evaluate(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty)
        {
            return PasswordStrengthLevel.VeryWeak;
        }

        var length = password.Length;
        var hasLower = false;
        var hasUpper = false;
        var hasDigit = false;
        var hasSymbol = false;

        foreach (var ch in password)
        {
            if (char.IsLower(ch))
            {
                hasLower = true;
            }
            else if (char.IsUpper(ch))
            {
                hasUpper = true;
            }
            else if (char.IsDigit(ch))
            {
                hasDigit = true;
            }
            else
            {
                hasSymbol = true;
            }
        }

        var classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);

        if (length < 8)
        {
            return classes >= 3 && length >= 6 ? PasswordStrengthLevel.Weak : PasswordStrengthLevel.VeryWeak;
        }

        if (length < 12)
        {
            return classes >= 3 ? PasswordStrengthLevel.Fair : PasswordStrengthLevel.Weak;
        }

        if (classes < 3)
        {
            return PasswordStrengthLevel.Fair;
        }

        return length >= 16 ? PasswordStrengthLevel.VeryStrong : PasswordStrengthLevel.Strong;
    }
}
