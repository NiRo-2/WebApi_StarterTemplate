namespace WebApi.Services
{
    /// <summary>
    /// Password reset tokens cleanup service which run every x hours and remove all expired tokens from db
    /// </summary>
    public class PasswordResetTokenCleanupService : IHostedService, IDisposable
    {
        private readonly IServiceProvider _services;
        private readonly IConfiguration _configuration;
        private Timer _timer;

        public PasswordResetTokenCleanupService(IServiceProvider services, IConfiguration configuration)
        {
            _services = services;
            _configuration = configuration;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            // Create a timer that runs the cleanup method every day
            _timer = new Timer(DoCleanup, null, TimeSpan.Zero, TimeSpan.FromHours(_configuration.GetValue<int>("CleanningServices:ExpiredPasswordResetTokens_CleanupIntervalHours")));

            // Remove all records from the Password reset tokens table on startup
            RemoveAllPasswordResetTokens();

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _timer?.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }

        //empty all password reset tokens from db on load because we no longer have it's encryption keys (they are dynamic and created on load as well)
        private async void RemoveAllPasswordResetTokens()
        {
            using (var scope = _services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                // Remove all records from the ActiveSessions table
                dbContext.PasswordResetTokens.RemoveRange(dbContext.PasswordResetTokens);

                // Save changes to the database
                await dbContext.SaveChangesAsync();
            }
        }

        private void DoCleanup(object state)
        {
            using (var scope = _services.CreateScope())
            {
                var serviceProvider = scope.ServiceProvider;
                var tokenService = serviceProvider.GetRequiredService<IPasswordResetTokenService>();

                // Call your method to remove expired tokens
                tokenService.RemoveExpiredTokensAsync().GetAwaiter().GetResult();
            }
        }

        public void Dispose()
        {
            _timer?.Dispose();
        }
    }
}