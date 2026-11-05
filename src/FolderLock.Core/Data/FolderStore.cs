using FolderLock.Core.Security;
using Microsoft.Data.Sqlite;

namespace FolderLock.Core.Data;

public sealed class FolderStore
{
    private const string SelectColumns =
        """
        Id, Path, DisplayName, PasswordHash, IsLocked, DaclSddl,
        AccessRulesProtected, EncryptionMode, RecoveryHash, CreatedAt, LastLockedAt,
        ProtectedRecoveryCode, VaultPath, FailedAttempts, LockoutUntil, OwnerSid, OriginalAttributes,
        PasswordHintProtected, RecoveryBackedUpAt
        """;

    private readonly string _connectionString;
    private readonly string _databasePath;
    private readonly byte[]? _key;

    static FolderStore()
    {
        SQLitePCL.Batteries_V2.Init();
    }

    public FolderStore(string? databasePath = null, byte[]? key = null)
    {
        var path = databasePath ?? GetDefaultDatabasePath();
        var directory = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _databasePath = path;
        _key = key is { Length: > 0 } ? key : null;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString();
    }

    public static string GetCipherVersion()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA cipher_version;";
        return command.ExecuteScalar()?.ToString() ?? string.Empty;
    }

    public static string GetDefaultDatabasePath()
    {
        return System.IO.Path.Combine(AppPaths.DataDirectory, "folderlock.db");
    }

    public void Initialize()
    {
        if (_key is not null && File.Exists(_databasePath) && IsPlaintextDatabase(_databasePath))
        {
            MigratePlaintextToEncrypted();
        }

        using var connection = OpenConnection();
        CreateSchema(connection);
        EnsureColumns(connection);
    }

    private static void EnsureColumns(SqliteConnection connection)
    {
        EnsureColumn(connection, "ProtectedRecoveryCode", "TEXT NULL");
        EnsureColumn(connection, "VaultPath", "TEXT NULL");
        EnsureColumn(connection, "FailedAttempts", "INTEGER NOT NULL DEFAULT 0");
        EnsureColumn(connection, "LockoutUntil", "TEXT NULL");
        EnsureColumn(connection, "OwnerSid", "TEXT NULL");
        EnsureColumn(connection, "OriginalAttributes", "INTEGER NULL");
        EnsureColumn(connection, "PasswordHintProtected", "TEXT NULL");
        EnsureColumn(connection, "RecoveryBackedUpAt", "TEXT NULL");
    }

    private static void CreateSchema(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            """
                CREATE TABLE IF NOT EXISTS Folders (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Path TEXT NOT NULL UNIQUE,
                    DisplayName TEXT NOT NULL,
                    PasswordHash TEXT NULL,
                    IsLocked INTEGER NOT NULL DEFAULT 0,
                    DaclSddl TEXT NULL,
                    AccessRulesProtected INTEGER NOT NULL DEFAULT 0,
                    EncryptionMode INTEGER NOT NULL DEFAULT 0,
                    RecoveryHash TEXT NULL,
                    CreatedAt TEXT NOT NULL,
                    LastLockedAt TEXT NULL,
                    ProtectedRecoveryCode TEXT NULL,
                    VaultPath TEXT NULL,
                    FailedAttempts INTEGER NOT NULL DEFAULT 0,
                    LockoutUntil TEXT NULL,
                    OwnerSid TEXT NULL,
                    OriginalAttributes INTEGER NULL,
                    PasswordHintProtected TEXT NULL,
                    RecoveryBackedUpAt TEXT NULL
                );

                CREATE TABLE IF NOT EXISTS VaultKeySlots (
                    SlotId TEXT PRIMARY KEY,
                    FolderId INTEGER NOT NULL,
                    Kind INTEGER NOT NULL,
                    Label TEXT NULL,
                    ProtectedSecret TEXT NULL,
                    CreatedAt TEXT NOT NULL,
                    LastRevealedAt TEXT NULL
                );

                CREATE TABLE IF NOT EXISTS LocalUnlockKeys (
                    FolderId INTEGER PRIMARY KEY,
                    ProtectedKey TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS AuditLog (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FolderId INTEGER NULL,
                    FolderPath TEXT NULL,
                    Action TEXT NOT NULL,
                    Success INTEGER NOT NULL DEFAULT 1,
                    Detail TEXT NULL,
                    CreatedAt TEXT NOT NULL
                );
                """;
        command.ExecuteNonQuery();
    }

    public void AddAudit(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO AuditLog (FolderId, FolderPath, Action, Success, Detail, CreatedAt)
            VALUES ($folderId, $folderPath, $action, $success, $detail, $createdAt);
            """;
        command.Parameters.AddWithValue("$folderId", (object?)entry.FolderId ?? DBNull.Value);
        command.Parameters.AddWithValue("$folderPath", (object?)entry.FolderPath ?? DBNull.Value);
        command.Parameters.AddWithValue("$action", entry.Action);
        command.Parameters.AddWithValue("$success", entry.Success ? 1 : 0);
        command.Parameters.AddWithValue("$detail", (object?)entry.Detail ?? DBNull.Value);
        command.Parameters.AddWithValue("$createdAt", entry.CreatedAt.UtcDateTime.ToString("O"));
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<AuditEntry> GetAudit(int limit = 500)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT Id, FolderId, FolderPath, Action, Success, Detail, CreatedAt
            FROM AuditLog
            ORDER BY Id DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);

        var results = new List<AuditEntry>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(new AuditEntry
            {
                Id = reader.GetInt64(0),
                FolderId = reader.IsDBNull(1) ? null : reader.GetInt64(1),
                FolderPath = reader.IsDBNull(2) ? null : reader.GetString(2),
                Action = reader.GetString(3),
                Success = reader.GetInt64(4) != 0,
                Detail = reader.IsDBNull(5) ? null : reader.GetString(5),
                CreatedAt = DateTimeOffset.Parse(reader.GetString(6), null, System.Globalization.DateTimeStyles.RoundtripKind),
            });
        }

        return results;
    }

    public void ClearAudit()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM AuditLog;";
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<FolderRecord> GetAll()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {SelectColumns} FROM Folders ORDER BY DisplayName COLLATE NOCASE;";

        var results = new List<FolderRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(ReadRecord(reader));
        }

        return results;
    }

    public FolderRecord? GetById(long id)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {SelectColumns} FROM Folders WHERE Id = $id;";
        command.Parameters.AddWithValue("$id", id);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRecord(reader) : null;
    }

    public FolderRecord? GetByPath(string path)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {SelectColumns} FROM Folders WHERE Path = $path COLLATE NOCASE;";
        command.Parameters.AddWithValue("$path", path);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRecord(reader) : null;
    }

    public FolderRecord Insert(FolderRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO Folders
                (Path, DisplayName, PasswordHash, IsLocked, DaclSddl,
                 AccessRulesProtected, EncryptionMode, RecoveryHash, CreatedAt, LastLockedAt,
                 ProtectedRecoveryCode, VaultPath, FailedAttempts, LockoutUntil, OwnerSid, OriginalAttributes,
                 PasswordHintProtected, RecoveryBackedUpAt)
            VALUES
                ($path, $displayName, $passwordHash, $isLocked, $daclSddl,
                 $accessRulesProtected, $encryptionMode, $recoveryHash, $createdAt, $lastLockedAt,
                 $protectedRecoveryCode, $vaultPath, $failedAttempts, $lockoutUntil, $ownerSid, $originalAttributes,
                 $passwordHintProtected, $recoveryBackedUpAt);
            SELECT last_insert_rowid();
            """;
        AddRecordParameters(command, record);

        record.Id = (long)(command.ExecuteScalar() ?? 0L);
        return record;
    }

    public void Update(FolderRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE Folders SET
                Path = $path,
                DisplayName = $displayName,
                PasswordHash = $passwordHash,
                IsLocked = $isLocked,
                DaclSddl = $daclSddl,
                AccessRulesProtected = $accessRulesProtected,
                EncryptionMode = $encryptionMode,
                RecoveryHash = $recoveryHash,
                CreatedAt = $createdAt,
                LastLockedAt = $lastLockedAt,
                ProtectedRecoveryCode = $protectedRecoveryCode,
                VaultPath = $vaultPath,
                FailedAttempts = $failedAttempts,
                LockoutUntil = $lockoutUntil,
                OwnerSid = $ownerSid,
                OriginalAttributes = $originalAttributes,
                PasswordHintProtected = $passwordHintProtected,
                RecoveryBackedUpAt = $recoveryBackedUpAt
            WHERE Id = $id;
            """;
        AddRecordParameters(command, record);
        command.Parameters.AddWithValue("$id", record.Id);
        command.ExecuteNonQuery();
    }

    public void Delete(long id)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            DELETE FROM Folders WHERE Id = $id;
            DELETE FROM VaultKeySlots WHERE FolderId = $id;
            DELETE FROM LocalUnlockKeys WHERE FolderId = $id;
            """;
        command.Parameters.AddWithValue("$id", id);
        command.ExecuteNonQuery();
    }

    public void ReplaceVaultKeySlots(long folderId, IEnumerable<VaultKeySlotRecord> slots)
    {
        ArgumentNullException.ThrowIfNull(slots);

        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction();

        using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM VaultKeySlots WHERE FolderId = $folderId;";
            delete.Parameters.AddWithValue("$folderId", folderId);
            delete.ExecuteNonQuery();
        }

        foreach (var slot in slots)
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO VaultKeySlots
                    (SlotId, FolderId, Kind, Label, ProtectedSecret, CreatedAt, LastRevealedAt)
                VALUES
                    ($slotId, $folderId, $kind, $label, $protectedSecret, $createdAt, $lastRevealedAt);
                """;
            insert.Parameters.AddWithValue("$slotId", slot.SlotId.ToString("D"));
            insert.Parameters.AddWithValue("$folderId", folderId);
            insert.Parameters.AddWithValue("$kind", (int)slot.Kind);
            insert.Parameters.AddWithValue("$label", (object?)slot.Label ?? DBNull.Value);
            insert.Parameters.AddWithValue("$protectedSecret", (object?)slot.ProtectedSecret ?? DBNull.Value);
            insert.Parameters.AddWithValue("$createdAt", slot.CreatedAt.UtcDateTime.ToString("O"));
            insert.Parameters.AddWithValue(
                "$lastRevealedAt",
                slot.LastRevealedAt is { } revealed ? revealed.UtcDateTime.ToString("O") : DBNull.Value);
            insert.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    public IReadOnlyList<VaultKeySlotRecord> GetVaultKeySlots(long folderId)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT SlotId, FolderId, Kind, Label, ProtectedSecret, CreatedAt, LastRevealedAt
            FROM VaultKeySlots
            WHERE FolderId = $folderId
            ORDER BY CreatedAt;
            """;
        command.Parameters.AddWithValue("$folderId", folderId);

        var results = new List<VaultKeySlotRecord>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(new VaultKeySlotRecord
            {
                SlotId = Guid.Parse(reader.GetString(0)),
                FolderId = reader.GetInt64(1),
                Kind = (VaultSlotKind)reader.GetInt32(2),
                Label = reader.IsDBNull(3) ? null : reader.GetString(3),
                ProtectedSecret = reader.IsDBNull(4) ? null : reader.GetString(4),
                CreatedAt = DateTimeOffset.Parse(
                    reader.GetString(5),
                    null,
                    System.Globalization.DateTimeStyles.RoundtripKind),
                LastRevealedAt = reader.IsDBNull(6)
                    ? null
                    : DateTimeOffset.Parse(
                        reader.GetString(6),
                        null,
                        System.Globalization.DateTimeStyles.RoundtripKind),
            });
        }

        return results;
    }

    public void MarkVaultKeySlotRevealed(Guid slotId, DateTimeOffset revealedAt)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            "UPDATE VaultKeySlots SET LastRevealedAt = $revealedAt WHERE SlotId = $slotId;";
        command.Parameters.AddWithValue("$slotId", slotId.ToString("D"));
        command.Parameters.AddWithValue("$revealedAt", revealedAt.UtcDateTime.ToString("O"));
        command.ExecuteNonQuery();
    }

    public string? GetLocalUnlockKey(long folderId)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ProtectedKey FROM LocalUnlockKeys WHERE FolderId = $folderId;";
        command.Parameters.AddWithValue("$folderId", folderId);
        var value = command.ExecuteScalar();
        return value is null or DBNull ? null : value.ToString();
    }

    public void SaveLocalUnlockKey(long folderId, string protectedKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedKey);

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO LocalUnlockKeys (FolderId, ProtectedKey)
            VALUES ($folderId, $protectedKey)
            ON CONFLICT(FolderId) DO UPDATE SET ProtectedKey = excluded.ProtectedKey;
            """;
        command.Parameters.AddWithValue("$folderId", folderId);
        command.Parameters.AddWithValue("$protectedKey", protectedKey);
        command.ExecuteNonQuery();
    }

    public void DeleteLocalUnlockKey(long folderId)
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM LocalUnlockKeys WHERE FolderId = $folderId;";
        command.Parameters.AddWithValue("$folderId", folderId);
        command.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();

        if (_key is not null)
        {
            ApplyKey(connection, _key);
        }

        return connection;
    }

    private static void ApplyKey(SqliteConnection connection, byte[] key)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA key = \"x'{Convert.ToHexString(key)}'\";";
        command.ExecuteNonQuery();

        using var check = connection.CreateCommand();
        check.CommandText = "SELECT count(*) FROM sqlite_master;";
        check.ExecuteScalar();
    }

    private static bool IsPlaintextDatabase(string path)
    {
        try
        {
            var connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString();

            using var connection = new SqliteConnection(connectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_master;";
            command.ExecuteScalar();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void MigratePlaintextToEncrypted()
    {
        var plainPath = _databasePath + ".plain";
        File.Move(_databasePath, plainPath, overwrite: true);

        var tables = new[] { "Folders", "AuditLog", "VaultKeySlots", "LocalUnlockKeys" };
        try
        {
            using (var source = new SqliteConnection(
                       new SqliteConnectionStringBuilder { DataSource = plainPath, Pooling = false }.ToString()))
            {
                source.Open();

                using (var target = OpenConnection())
                {
                    CreateSchema(target);
                    EnsureColumns(target);

                    using (var transaction = target.BeginTransaction())
                    {
                        foreach (var table in tables)
                        {
                            if (TableExists(source, table))
                            {
                                CopyTable(source, target, table, transaction);
                            }
                        }

                        transaction.Commit();
                    }

                    // 只有逐表行数完全一致才删除原始明文库，否则回滚到明文库。
                    VerifyCopy(source, target, tables);
                }
            }

            File.Delete(plainPath);
        }
        catch
        {
            TryDeleteFile(_databasePath);

            try
            {
                File.Move(plainPath, _databasePath, overwrite: true);
            }
            catch
            {
            }

            throw;
        }
    }

    private static void VerifyCopy(SqliteConnection source, SqliteConnection target, IEnumerable<string> tables)
    {
        foreach (var table in tables)
        {
            if (!TableExists(source, table))
            {
                continue;
            }

            var expected = CountRows(source, table);
            var actual = TableExists(target, table) ? CountRows(target, table) : 0;
            if (expected != actual)
            {
                throw new InvalidOperationException(
                    $"明文库迁移校验失败：表 {table} 期望 {expected} 行，实际 {actual} 行。已保留原始明文库。");
            }
        }
    }

    private static long CountRows(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table};";
        return Convert.ToInt64(command.ExecuteScalar() ?? 0L);
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    private static bool TableExists(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=$name;";
        command.Parameters.AddWithValue("$name", table);
        return Convert.ToInt64(command.ExecuteScalar() ?? 0L) > 0;
    }

    private static void CopyTable(
        SqliteConnection source,
        SqliteConnection target,
        string table,
        SqliteTransaction transaction)
    {
        using var read = source.CreateCommand();
        read.CommandText = $"SELECT * FROM {table};";
        using var reader = read.ExecuteReader();

        var columns = Enumerable.Range(0, reader.FieldCount).Select(reader.GetName).ToList();
        var columnList = string.Join(", ", columns);
        var parameterList = string.Join(", ", columns.Select(column => "$" + column));

        while (reader.Read())
        {
            using var insert = target.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = $"INSERT INTO {table} ({columnList}) VALUES ({parameterList});";
            for (var i = 0; i < columns.Count; i++)
            {
                insert.Parameters.AddWithValue(
                    "$" + columns[i],
                    reader.IsDBNull(i) ? DBNull.Value : reader.GetValue(i));
            }

            insert.ExecuteNonQuery();
        }
    }

    private static void EnsureColumn(SqliteConnection connection, string column, string definition)
    {
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA table_info(Folders);";
        using var reader = pragma.ExecuteReader();
        while (reader.Read())
        {
            if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }

        using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE Folders ADD COLUMN {column} {definition};";
        alter.ExecuteNonQuery();
    }

    private static void AddRecordParameters(SqliteCommand command, FolderRecord record)
    {
        command.Parameters.AddWithValue("$path", record.Path);
        command.Parameters.AddWithValue("$displayName", record.DisplayName);
        command.Parameters.AddWithValue("$passwordHash", (object?)record.PasswordHash ?? DBNull.Value);
        command.Parameters.AddWithValue("$isLocked", record.IsLocked ? 1 : 0);
        command.Parameters.AddWithValue("$daclSddl", (object?)record.DaclSddl ?? DBNull.Value);
        command.Parameters.AddWithValue("$accessRulesProtected", record.AccessRulesProtected ? 1 : 0);
        command.Parameters.AddWithValue("$encryptionMode", (int)record.EncryptionMode);
        command.Parameters.AddWithValue("$recoveryHash", (object?)record.RecoveryHash ?? DBNull.Value);
        command.Parameters.AddWithValue("$createdAt", record.CreatedAt.UtcDateTime.ToString("O"));
        command.Parameters.AddWithValue(
            "$lastLockedAt",
            record.LastLockedAt is { } last ? last.UtcDateTime.ToString("O") : DBNull.Value);
        command.Parameters.AddWithValue(
            "$protectedRecoveryCode",
            (object?)record.ProtectedRecoveryCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$vaultPath", (object?)record.VaultPath ?? DBNull.Value);
        command.Parameters.AddWithValue("$failedAttempts", record.FailedAttempts);
        command.Parameters.AddWithValue(
            "$lockoutUntil",
            record.LockoutUntil is { } lockout ? lockout.UtcDateTime.ToString("O") : DBNull.Value);
        command.Parameters.AddWithValue("$ownerSid", (object?)record.OwnerSid ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$originalAttributes",
            record.OriginalAttributes is { } attributes ? (long)attributes : DBNull.Value);
        command.Parameters.AddWithValue(
            "$passwordHintProtected",
            (object?)record.PasswordHintProtected ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$recoveryBackedUpAt",
            record.RecoveryBackedUpAt is { } backedUp ? backedUp.UtcDateTime.ToString("O") : DBNull.Value);
    }

    private static FolderRecord ReadRecord(SqliteDataReader reader)
    {
        return new FolderRecord
        {
            Id = reader.GetInt64(0),
            Path = reader.GetString(1),
            DisplayName = reader.GetString(2),
            PasswordHash = reader.IsDBNull(3) ? null : reader.GetString(3),
            IsLocked = reader.GetInt64(4) != 0,
            DaclSddl = reader.IsDBNull(5) ? null : reader.GetString(5),
            AccessRulesProtected = reader.GetInt64(6) != 0,
            EncryptionMode = (EncryptionMode)reader.GetInt64(7),
            RecoveryHash = reader.IsDBNull(8) ? null : reader.GetString(8),
            CreatedAt = DateTimeOffset.Parse(reader.GetString(9), null, System.Globalization.DateTimeStyles.RoundtripKind),
            LastLockedAt = reader.IsDBNull(10)
                ? null
                : DateTimeOffset.Parse(reader.GetString(10), null, System.Globalization.DateTimeStyles.RoundtripKind),
            ProtectedRecoveryCode = reader.IsDBNull(11) ? null : reader.GetString(11),
            VaultPath = reader.IsDBNull(12) ? null : reader.GetString(12),
            FailedAttempts = reader.GetInt32(13),
            LockoutUntil = reader.IsDBNull(14)
                ? null
                : DateTimeOffset.Parse(reader.GetString(14), null, System.Globalization.DateTimeStyles.RoundtripKind),
            OwnerSid = reader.IsDBNull(15) ? null : reader.GetString(15),
            OriginalAttributes = reader.IsDBNull(16) ? null : (uint)reader.GetInt64(16),
            PasswordHintProtected = reader.IsDBNull(17) ? null : reader.GetString(17),
            RecoveryBackedUpAt = reader.IsDBNull(18)
                ? null
                : DateTimeOffset.Parse(reader.GetString(18), null, System.Globalization.DateTimeStyles.RoundtripKind),
        };
    }
}
