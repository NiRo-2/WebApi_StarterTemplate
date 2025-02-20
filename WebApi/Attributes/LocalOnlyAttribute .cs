using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using NLog;
using NLog.Web;
using System.Net;

namespace BackEnd_Exp.Attributes
{
    /// <summary>
    /// Allow access to controller methods for local access only.
    /// to allow access to local addresses and block all others for certain method, add [LocalOnly] on top of the method
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
    public class LocalOnlyAttribute : ActionFilterAttribute
    {
        Logger logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

        // Local IP addresses
        private readonly IPAddress[] localAddresses = {
        IPAddress.Parse("127.0.0.1"),
        IPAddress.Parse("::1"),
        IPAddress.Parse("::ffff:127.0.0.1")
    };

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            try
            {
                IPAddress remoteIp = context.HttpContext.Connection.RemoteIpAddress;
                foreach (IPAddress allowedIp in localAddresses)
                {
                    if (IPAddress.Equals(remoteIp, allowedIp))
                    {
                        // Address found
                        logger.Info("Connection allowed from local IP: " + remoteIp);
                        return;
                    }
                }

                // If we are here, the IP is not allowed
                logger.Warn("Connection denied from non-local IP: " + remoteIp);
                context.Result = new UnauthorizedResult();
            }
            catch (Exception ex)
            {
                logger.Error("Error getting remote IP address. Err: " + ex.Message);
            }
        }
    }
}