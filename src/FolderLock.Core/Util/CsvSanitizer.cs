namespace FolderLock.Core.Util;

/// <summary>CSV 单元格转义，并阻止电子表格公式注入（= + - @ 以及制表/回车开头）。</summary>
public static class CsvSanitizer
{
    private static readonly char[] FormulaPrefixes = { '=', '+', '-', '@', '\t', '\r' };

    public static string Escape(string? value)
    {
        var text = value ?? string.Empty;

        if (text.Length > 0 && Array.IndexOf(FormulaPrefixes, text[0]) >= 0)
        {
            text = "'" + text;
        }

        if (text.Contains(',') || text.Contains('"') || text.Contains('\n') || text.Contains('\r'))
        {
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }

        return text;
    }
}
