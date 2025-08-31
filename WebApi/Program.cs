using Microsoft.Data.Sqlite;
using NLog;
using NLog.Web;
using NrExtras.EncryptionHelper;
using NrExtras.RandomPasswordGenerator;
using System.Net;
using WebApi.Services;

namespace WebApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Logger logger = LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
            // Check and create the Logs table in SQLite
            CreateLogsTable();

            // Early init of NLog to allow startup and exception logging, before host is built
            logger.Info("Init main");

            try
            {
                // Set jwt key and encrypt it
                GlobalDynamicSettings.JwtTokenSecret_HashedSecnret = EncryptionHelper.EncryptKey(RandomPasswordGenerator.Generate512BitPassword());
                // Set debug mode
                GlobalDynamicSettings.DebugMode_RunningLocal = IsDevelopmentEnvironment();
                if (GlobalDynamicSettings.DebugMode_RunningLocal)
                    logger.Info("Ruuning on debugMode running local");
                else
                    logger.Info("Running production");

                //build
                var builder = WebApplication.CreateBuilder(args);

                //get email pass based on env
                if (IsDevelopmentEnvironment())
                    GlobalDynamicSettings.EmailHashedPass = builder.Configuration["EmailSettings:Password:local"] ?? "";
                else
                    GlobalDynamicSettings.EmailHashedPass = builder.Configuration["EmailSettings:Password:production"] ?? "";

                // Add services to the container.
                var startup = new Startup(builder.Configuration);
                startup.ConfigureServices(builder.Services); // calling ConfigureServices method
                builder.Services.AddControllers();

                #region NLog: Setup NLog for Dependency injection
                builder.Logging.ClearProviders();
                builder.Host.UseNLog();
                #endregion

                // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
                builder.Services.AddEndpointsApiExplorer();
                builder.Services.AddSwaggerGen();

                //if using production and domain - load cert provider for auto cert loading
                if (!IsDevelopmentEnvironment() && bool.Parse(builder.Configuration["UseDomain"] ?? "false"))
                {
                    var pfxPath = builder.Configuration["PfxFilePath"] ?? "";
                    if (!File.Exists(pfxPath))
                        throw new FileNotFoundException($"PFX file not found at {pfxPath}");

                    logger.Info($"Using PFX file for SSL: {pfxPath}");
                    // register provider once (DI will dispose it at shutdown)
                    builder.Services.AddSingleton<ReloadableCertificateProvider>(sp =>
                    {
                        var pfxPath = builder.Configuration["PfxFilePath"] ?? throw new InvalidOperationException("PfxFilePath not set");
                        return new ReloadableCertificateProvider(pfxPath);
                    });
                }

                // Configure Kestrel settings - longer time out
                builder.WebHost.ConfigureKestrel(options =>
                {
                    // Set global timeouts
                    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(60);

                    //set auto ssl for production with domain only
                    if (!IsDevelopmentEnvironment() && bool.Parse(builder.Configuration["UseDomain"] ?? throw new Exception("Invalid UseDomain")) == true)
                    {
                        try
                        {
                            //get the port from config
                            int.TryParse(builder.Configuration["ListeningUrls:production_WithDomain"], out int sslPort);
                            if (sslPort <= 0)
                            {
                                logger.Error("Invalid port configuration for SSL: 'ListeningUrls:production_WithDomain' is not set or invalid.");
                                throw new Exception("Invalid port configuration for SSL.");
                            }

                            //Set listen port with the auto load cert loader
                            options.Listen(IPAddress.Any, sslPort, listenOptions =>
                            {
                                listenOptions.UseHttps(httpsOptions =>
                                {
                                    // Resolve the provider from the listener's application services once (captured)
                                    var provider = listenOptions.ApplicationServices.GetRequiredService<ReloadableCertificateProvider>();

                                    // Called for each TLS handshake — return current cert (thread-safe in your provider)
                                    httpsOptions.ServerCertificateSelector = (connectionContext, sniName) =>
                                    {
                                        var cert = provider.GetCertificate();
                                        if (cert == null)
                                        {
                                            logger.Error("No certificate available for handshake.");
                                            return null;
                                        }
                                        return cert;
                                    };
                                });
                            });
                        }
                        catch (Exception ex)
                        {
                            logger.Error(ex, "Error configuring Kestrel for SSL");
                            throw; // Re-throw the exception to ensure the application fails to start
                        }
                    }
                });

                //build the app with all configs
                using (var app = builder.Build())
                {
                    startup.Configure(app, builder.Environment); // calling Configure method
                    var configuration = app.Services.GetRequiredService<IConfiguration>();

                    // Configure the HTTP request pipeline - set right listenning urls and ports
                    if (IsDevelopmentEnvironment())
                    {//dev
                        builder.WebHost.UseUrls(configuration["ListeningUrls:local"] ?? ""); //set dev running urls
                    }
                    else
                    {//production
                        if (bool.Parse(configuration["UseDomain"] ?? throw new Exception("Invalid UseDomain")) == false)//if we dont have a domain, set the right ports to listen
                            builder.WebHost.UseUrls(configuration["ListeningUrls:production_WithoutDomain"] ?? "");
                    }

                    app.UseHttpsRedirection();
                    app.UseAuthorization();
                    app.MapControllers();
                    app.Run();
                }
            }
            catch (Exception ex)
            {
                // NLog: catch setup errors
                logger.Error(ex, "Stopped program because of exception");
                logger.Trace(ex);
                throw; // Re-throw the exception to ensure the application fails to start
            }
            finally
            {
                // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
                LogManager.Shutdown();
            }
        }

        /// <summary>
        /// Check if we are in developing environment
        /// </summary>
        /// <returns>true if true, false otherwise</returns>
        private static bool IsDevelopmentEnvironment()
        {
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
                             ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")
                             ?? "Production"; // default fallback

            return environment.Trim().Equals("Development", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Create SQLite log tables
        /// </summary>
        private static void CreateLogsTable()
        {
            string dbDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");

            if (!Directory.Exists(dbDirectory))
                Directory.CreateDirectory(dbDirectory);  // Create the 'logs' directory if it doesn't exist

            string connectionString = $"Data Source={Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", "nlog-database.sqlite")}";
            using (var connection = new SqliteConnection(connectionString))
            {
                connection.Open();

                //important logs table
                string createOwnLogsTable = @"
                    CREATE TABLE IF NOT EXISTS OwnLogs (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        TimeStamp TEXT,
                        LogLevel TEXT,
                        Logger TEXT,
                        Message TEXT,
                        Exception TEXT
                    );";

                using (var command = new SqliteCommand(createOwnLogsTable, connection))
                    command.ExecuteNonQuery();
            }
        }
    }
}