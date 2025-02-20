using NLog;
using NLog.Web;
using NrExtras.NetAddressUtils;
using System.Net;
using System.Net.Sockets;

namespace WebApi
{
    /// <summary>
    /// Inchagre of blocking ips
    /// </summary>
    public class IpBlacklistMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly List<IPAddress> _blacklistedIps;
        private readonly Logger logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

        public IpBlacklistMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            try
            {
                var ipAddresses = configuration.GetSection("IpBlacklist").Get<List<string>>();
                
                //incase of empty list
                if (ipAddresses == null) //empty list
                    _blacklistedIps = new List<IPAddress>();
                else// Expand IP ranges
                    _blacklistedIps = ipAddresses.SelectMany(ExpandIpAddressRange).ToList();
            }
            catch (Exception ex)
            {
                // Log error and create an empty list to prevent app crash
                logger.Error(ex);
                _blacklistedIps = new List<IPAddress>();
            }
        }

        /// <summary>
        /// Parse address. can handle single ip and range for example: 127.0.0.1-127.0.0.254
        /// </summary>
        /// <param name="ipAddress">single ip address or range for example: 127.0.0.1-127.0.0.254</param>
        /// <returns>list of ips</returns>
        /// <exception cref="ArgumentException"></exception>
        private static List<IPAddress> ExpandIpAddressRange(string ipAddress)
        {
            if (!ipAddress.Contains("-"))
                return new List<IPAddress> { IPAddress.Parse(ipAddress) };

            string[] parts = ipAddress.Split('-');
            IPAddress startAddress = IPAddress.Parse(parts[0]);
            IPAddress endAddress = IPAddress.Parse(parts[1]);

            // Validate IP range format (start <= end)
            if (startAddress.GetAddressBytes()[0] > endAddress.GetAddressBytes()[0])
                throw new ArgumentException($"Invalid IP range: {ipAddress} (Start address should be less than or equal to end address)");

            //get list
            List<IPAddress> iPAddresses = IpAndHost_Helper.GetIpRange(startAddress, endAddress);

            return iPAddresses;
        }

        /// <summary>
        /// active functino for checking and blocking ip
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task InvokeAsync(HttpContext context)
        {
            string clientIpString = context.Connection.RemoteIpAddress?.ToString();

            if (clientIpString == null)
            {
                // Log a warning if client IP cannot be retrieved
                logger.Warn("Failed to retrieve client IP address.");
                await _next(context);
                return;
            }

            IPAddress clientIp;
            if (!IPAddress.TryParse(clientIpString, out clientIp))
            {
                // Log an error if IP parsing fails
                logger.Error($"Failed to parse client IP address: {clientIpString}");
                await _next(context);
                return;
            }

            // Convert IPv6 address to IPv4 if necessary (already implemented)
            clientIp = ConvertToIPv4(clientIp);

            if (_blacklistedIps.Contains(clientIp))
            {
                context.Response.StatusCode = 429;
                logger.Warn($"Request blocked due to IP address being blacklisted. IpAddress: {clientIp}");
                await context.Response.WriteAsync("Request blocked due to IP address being blacklisted.");
                return;
            }

            await _next(context);
        }

        /// <summary>
        /// Convert any ip to ip v4
        /// </summary>
        /// <param name="ipAddress">ip address</param>
        /// <returns>ip v4</returns>
        private IPAddress ConvertToIPv4(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // IPv6 address, try to map to IPv4
                try
                {
                    return ipAddress.MapToIPv4();
                }
                catch (FormatException)
                {
                    // IPv6 address cannot be mapped to IPv4, log a warning
                    logger.Warn($"IPv6 address {ipAddress} cannot be mapped to IPv4.");
                    return ipAddress; // Return original IPv6 address
                }
            }

            // IPv4 address, return as is
            return ipAddress;
        }
    }
}