using Microsoft.IdentityModel.Tokens;
using NrExtras.EncryptionHelper;
using NrExtras.Logger;
using NrExtras.RandomPasswordGenerator;

namespace WebApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Set jwt key and encrypt it
            GlobalDynamicSettings.JwtTokenSecret_HashedSecnret = EncryptionHelper.EncryptKey(RandomPasswordGenerator.Generate512BitPassword());
            // Set debug mode
            GlobalDynamicSettings.DebugMode_RunningLocal = IsDevelopmentEnvironment();

            //get config and email pass
            IConfiguration appSettingsConfiguration = GetConfiguration();
            if (IsDevelopmentEnvironment())
                GlobalDynamicSettings.EmailHashedPass = appSettingsConfiguration["EmailSettings:Password:local"];
            else
                GlobalDynamicSettings.EmailHashedPass = appSettingsConfiguration["EmailSettings:Password:production"];

            //build
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            var startup = new Startup(builder.Configuration);
            startup.ConfigureServices(builder.Services); // calling ConfigureServices method

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            //if running production and we have a domain, auto create ssl
            if (!IsDevelopmentEnvironment() && !appSettingsConfiguration.GetSection("LettuceEncrypt:DomainNames").Get<string[]>().IsNullOrEmpty())
            {
                Logger.WriteToLog("Auto creating ssl certificate using LettuceEncrypt");
                builder.Services.AddLettuceEncrypt();
                builder.WebHost.UseKestrel(k =>
                {
                    var appServices = k.ApplicationServices;
                    k.Listen(
                        System.Net.IPAddress.Any, int.Parse(appSettingsConfiguration["ListeningUrls:production_WithDomain"]),
                        o => o.UseHttps(h =>
                        {
                            h.UseLettuceEncrypt(appServices);
                        }));
                });
            }

            var app = builder.Build();
            startup.Configure(app, builder.Environment); // calling Configure method
            var configuration = app.Services.GetRequiredService<IConfiguration>();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();

                //setting running ports
                Logger.WriteToLog("Running on development env");
                builder.WebHost.UseUrls(configuration["ListeningUrls:local"]);
            }
            else
            {
                Logger.WriteToLog("Running on production env");
                //if we dont have a domain, set the right ports to listen
                if (configuration.GetSection("LettuceEncrypt:DomainNames").Get<string[]>().IsNullOrEmpty())
                    builder.WebHost.UseUrls(configuration["ListeningUrls:production_WithoutDomain"]);
            }

            app.UseHttpsRedirection();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }

        /// <summary>
        /// Check if we are in developing environment
        /// </summary>
        /// <returns>true if true, false otherwise</returns>
        private static bool IsDevelopmentEnvironment()
        {
            string environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            return environment?.ToLower() == "development";
        }

        /// <summary>
        /// get configuration object
        /// </summary>
        /// <param name="configFileName">default=appsettings.json</param>
        /// <returns>return configs object</returns>
        private static IConfiguration GetConfiguration(string configFileName = "appsettings.json")
        {
            return new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile(configFileName)
            .Build();
        }
    }
}