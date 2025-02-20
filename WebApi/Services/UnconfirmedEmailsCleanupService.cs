﻿using Microsoft.EntityFrameworkCore;
using NLog;
using NLog.Web;

namespace WebApi.Services
{
    // Service to clean up unconfirmed email records
    public class UnconfirmedEmailsCleanupService : IHostedService, IDisposable
    {
        private Logger logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

        private readonly IServiceProvider _services;
        private readonly IConfiguration _configuration;
        private Timer _timer;

        public UnconfirmedEmailsCleanupService(IServiceProvider services, IConfiguration configuration)
        {
            _services = services;
            _configuration = configuration;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            var cleanupIntervalHours = _configuration.GetValue<int>("UnconfirmedEmails_ExpirationHours");
            _timer = new Timer(DoWork, null, TimeSpan.Zero, TimeSpan.FromHours(cleanupIntervalHours));

            // Start cleanup task immediately on startup
            DoWork(null);

            return Task.CompletedTask;
        }

        private async void DoWork(object state)
        {
            using (var scope = _services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                // Calculate the datetime threshold for unconfirmed email records
                var expirationThreshold = DateTime.UtcNow.AddHours(-_configuration.GetValue<int>("UnconfirmedEmails_ExpirationHours"));

                try
                {
                    // Retrieve and remove unconfirmed email records older than the threshold
                    var unconfirmedEmails = await dbContext.Users
                        .Where(u => u.EmailConfirmed == 0 && u.RegistrationDate < expirationThreshold)
                        .ToListAsync();

                    if (unconfirmedEmails.Any())
                    {
                        // Remove the unconfirmed email records
                        dbContext.Users.RemoveRange(unconfirmedEmails);
                        await dbContext.SaveChangesAsync();
                        logger.Info($"UnconfirmedEmailsCleanupService - {unconfirmedEmails.Count} users with unconfirmed emails found and removed from db");
                    }
                }
                catch (DbUpdateConcurrencyException ex)
                {
                    // Handle concurrency exception (another process modified the data)
                    logger.Error($"Concurrency exception occurred: {ex.Message}");
                }
                catch (Exception ex)
                {
                    // Handle other exceptions
                    logger.Error($"An error occurred during cleanup: {ex.Message}");
                }
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