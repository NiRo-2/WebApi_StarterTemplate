using Microsoft.EntityFrameworkCore;
using NLog;
using NLog.Web;
using WebApi.Models;

namespace WebApi
{
    public class AppDbContext : DbContext
    {
        private readonly ILogger<AppDbContext> _logger;
        private readonly IConfiguration _configuration;
        private readonly int _maxRetries_OnDbIsLocked;

        //Constructor for dependency injection
        public AppDbContext(DbContextOptions<AppDbContext> options, IConfiguration configuration, ILogger<AppDbContext> logger) : base(options)
        {
            _configuration = configuration;
            _logger = logger;

            // Read the config value once
            _maxRetries_OnDbIsLocked = int.Parse(_configuration["SQLiteDB:maxRetries_WhenDbIsLocked"]
                ?? throw new Exception("Cannot read SQLiteDB:maxRetries_WhenDbIsLocked"));
        }

        public DbSet<User> Users { get; set; }
        public DbSet<ActiveSession> ActiveSessions { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        // SemaphoreSlim to handle concurrent access to the database
        private static readonly SemaphoreSlim _dbSemaphore = new(1, 1);

        //set auto values when saving new user
        public async override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            await _dbSemaphore.WaitAsync(cancellationToken);
            try
            {
                int retryCount = 0;

                while (true)
                {
                    try
                    {
                        // Set default values for Id and RegistrationDate before saving changes
                        foreach (var entry in ChangeTracker.Entries<User>())
                        {
                            if (entry.State == EntityState.Added)
                            {
                                entry.Entity.Id = NrExtras.GuidGenerator.GuidGenerator.generateGUID();
                                entry.Entity.RegistrationDate = DateTime.UtcNow;
                            }
                        }

                        return await base.SaveChangesAsync(cancellationToken);
                    }
                    catch (DbUpdateException ex) when (ex.InnerException is Microsoft.Data.Sqlite.SqliteException sqliteEx && sqliteEx.SqliteErrorCode == 5)
                    { // SQLite 'database is locked' error - use retry
                        retryCount++;
                        _logger.LogWarning($"SQLite 'database is locked' on SaveChangesAsync (attempt {retryCount})");

                        //check if we reached max retries
                        if (retryCount > _maxRetries_OnDbIsLocked)
                        {
                            _logger.LogError(ex, "Max retries reached in SaveChangesAsync");
                            throw; // rethrow original exception after retries
                        }

                        //still ok - delay and retry
                        await Task.Delay(100 * retryCount + Random.Shared.Next(50));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Unhandled exception in SaveChangesAsync");
                        throw new Exception("Error in SaveChangesAsync. Err: " + ex.Message, ex);
                    }
                }
            }
            finally
            {
                _dbSemaphore.Release();
            }
        }
    }
}