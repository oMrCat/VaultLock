namespace FolderLock.Core.Data;

public static class AppPaths
{
    private const string PortableFlag = "portable.flag";

    public static string ExecutableDirectory
    {
        get
        {
            var path = Environment.ProcessPath;
            return string.IsNullOrEmpty(path)
                ? AppContext.BaseDirectory
                : System.IO.Path.GetDirectoryName(path)!;
        }
    }

    public static bool IsPortable => File.Exists(System.IO.Path.Combine(ExecutableDirectory, PortableFlag));

    public static string DataDirectory => IsPortable
        ? System.IO.Path.Combine(ExecutableDirectory, "data")
        : System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "FolderLock");
}
