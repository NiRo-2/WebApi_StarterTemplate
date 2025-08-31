using NLog;
using NLog.Web;
using System.Security.Cryptography.X509Certificates;

namespace WebApi.Services
{
    public class ReloadableCertificateProvider : IDisposable
    {
        private readonly string _pfxPath;
        private readonly string _password;
        private X509Certificate2? _cachedCert;
        private FileSystemWatcher _watcher;
        private readonly object _lock = new();
        private Logger logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
        private DateTime _lastReload = DateTime.MinValue;

        /// <summary>
        /// Default constructor for cases where no PFX path is provided.
        /// </summary>
        public ReloadableCertificateProvider()
        {
            // Default constructor for cases where no PFX path is provided
            _pfxPath = string.Empty;
            _cachedCert = null;
            _password = string.Empty;
            _watcher = new FileSystemWatcher();
        }

        /// <summary>
        /// Constructor that initializes the certificate provider with a PFX file path.
        /// </summary>
        /// <param name="pfxPath"></param>
        /// <param name="password"></param>
        public ReloadableCertificateProvider(string pfxPath, string password = "")
        {
            _pfxPath = pfxPath;
            _password = password ?? throw new ArgumentNullException(nameof(password));
            LoadCertificate(); // Load the certificate initially

            // Watch file changes
            _watcher = new FileSystemWatcher(Path.GetDirectoryName(_pfxPath) ?? ".", Path.GetFileName(_pfxPath));
            _watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName;
            _watcher.Changed += OnChanged;
            _watcher.Created += OnChanged;
            _watcher.EnableRaisingEvents = true;
        }

        /// <summary>
        /// Loads the certificate from the PFX file.
        /// </summary>
        private void LoadCertificate()
        {
            lock (_lock)
            {
                _cachedCert?.Dispose();
                _cachedCert = X509CertificateLoader.LoadPkcs12FromFile(
                    _pfxPath,
                    _password,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet
                );
                logger.Info($"Certificate loaded/reloaded at {DateTime.Now}");
            }
        }

        /// <summary>
        /// OnChanged event handler for the file system watcher - reload the certificate when the file changes.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        /// <exception cref="InvalidOperationException"></exception>
        private void OnChanged(object sender, FileSystemEventArgs e)
        {
            var now = DateTime.UtcNow;
            if ((now - _lastReload).TotalSeconds < 2) return; // ignore rapid events
            _lastReload = now;

            try
            {
                //reload the certificate
                logger.Info($"Certificate file changed: {e.FullPath} at {DateTime.Now}");
                LoadCertificate();
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Failed to reload certificate");
            }
        }

        /// <summary>
        /// Retrieves the cached X.509 certificate.
        /// </summary>
        public X509Certificate2? GetCertificate()
        {
            lock (_lock) return _cachedCert;
        }

        /// <summary>
        /// Disposes the certificate provider, releasing any resources it holds.
        /// </summary>
        public void Dispose()
        {
            _watcher?.Dispose();
            _cachedCert?.Dispose();
        }
    }
}