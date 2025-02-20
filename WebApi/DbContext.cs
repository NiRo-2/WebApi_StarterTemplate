using Microsoft.EntityFrameworkCore;
using WebApi.Models;
using NLog;
using NLog.Web;

namespace WebApi
{
    public class AppDbContext : DbContext
    {
        Logger logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<User> Users { get; set; }
        public DbSet<ActiveSession> ActiveSessions { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        //set auto values when saving new user
        public async override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Set default values for Id and RegistrationDate before saving changes
                foreach (var entry in ChangeTracker.Entries<User>())
                {
                    if (entry.State == EntityState.Added)
                    {
                        entry.Entity.Id = NrExtras.GuidGenerator.GuidGenerator.generateGUID(); //uuid
                        entry.Entity.RegistrationDate = DateTime.UtcNow; //registration date - Now
                    }
                }

                return await base.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                logger.Error(ex);
                throw new Exception("Error in SaveChangesAsync. Err: " + ex.Message);
            }
        }
    }
}