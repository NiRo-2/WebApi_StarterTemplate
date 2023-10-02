using Microsoft.EntityFrameworkCore;
using WebApi.Models;

namespace WebApi
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<ActiveSession> ActiveSessions { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        //set auto values when saving new user
        public async override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
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
    }
}