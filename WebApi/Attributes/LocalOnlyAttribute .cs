using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using System;
using System.Net;
using System.Linq;
using NrExtras.Logger;

namespace BackEnd_Exp.Attributes
{
    /// <summary>
    /// Allow access to controller methods for local access only.
    /// to allow access to local addresses and block all others for certain method, add [LocalOnly] on top of the method
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
    public class LocalOnlyAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            try
            {
                var remoteIp = context.HttpContext.Connection.RemoteIpAddress;

                // Check if the remote IP is a loopback address (localhost)
                if (IPAddress.IsLoopback(remoteIp) || IPAddress.IPv6Loopback.Equals(remoteIp))
                {
                    Logger.WriteToLog("Connection allowed from local IP: " + remoteIp);
                }
                else
                {
                    Logger.WriteToLog("Connection denied from non-local IP: " + remoteIp, Logger.LogLevel.Warning);
                    context.Result = new UnauthorizedResult();
                }
            }
            catch (Exception ex)
            {
                Logger.WriteToLog("Error getting remote IP address. Err: " + ex.Message, Logger.LogLevel.Error);
            }
        }
    }
}