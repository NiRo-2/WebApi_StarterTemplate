using Microsoft.EntityFrameworkCore;

namespace WebApi
{
    //this service incharge of cleanning active sessions from expired sessions
    public class ExpiredSessionsCleanupService : IHostedService, IDisposable
    {
        private readonly IServiceProvider _services;
        private readonly IConfiguration _configuration;
        private Timer _timer;

        public ExpiredSessionsCleanupService(IServiceProvider services, IConfiguration configuration)
        {
            _services = services;
            _configuration = configuration;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            var cleanupIntervalHours = _configuration.GetValue<int>("ActiveSessions_CleanupIntervalHours");
            _timer = new Timer(DoWork, null, TimeSpan.Zero, TimeSpan.FromHours(cleanupIntervalHours));

            // Remove all records from the ActiveSessions table on startup
            RemoveAllActiveSessions();

            return Task.CompletedTask;
        }

        //empty all activeSessions from db on load because we no longer have it's encryption keys (they are dynamic and created on load as well)
        private async void RemoveAllActiveSessions()
        {
            using (var scope = _services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                // Remove all records from the ActiveSessions table
                dbContext.ActiveSessions.RemoveRange(dbContext.ActiveSessions);

                // Save changes to the database
                await dbContext.SaveChangesAsync();
            }
        }

        //clean up task
        private async void DoWork(object state)
        {
            using (var scope = _services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                // Calculate the datetime threshold for session expiration
                var expirationThreshold = DateTime.UtcNow.AddHours(-_configuration.GetValue<int>("JWT:TokenExpirationHours"));

                // Retrieve and remove expired sessions
                var expiredSessions = await dbContext.ActiveSessions.Where(s => s.SignInDate < expirationThreshold).ToListAsync();
                dbContext.ActiveSessions.RemoveRange(expiredSessions);

                // Save changes to the database
                await dbContext.SaveChangesAsync();
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _timer?.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            _timer?.Dispose();
        }
    }
}