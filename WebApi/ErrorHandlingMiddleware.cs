using NLog;
using NLog.Web;

namespace WebApi
{
    //error handling for unhandeld errors
    public class ErrorHandlingMiddleware
    {
        private Logger logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
        private readonly RequestDelegate _next;

        public ErrorHandlingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (BadHttpRequestException ex)
            {
                // Log and handle BadHttpRequestException with a 408 status code
                logger.Error($"Request body read timeout occurred: {ex.Message}");
                context.Response.StatusCode = StatusCodes.Status408RequestTimeout;
                await context.Response.WriteAsync("Request timed out. Please check your connection and try again.");
            }
            catch (OutOfMemoryException ex)
            {//out of memory exception - try to make garbage collection
                // Log the exception
                logger.Error($"OutOfMemoryException exception: {ex}");
                //collect garbage
                GC.Collect();

                // Return a error response to the client
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("An unexpected error occurred. Please try again in a few minutes.");
            }
            catch (Exception ex)
            {
                // Log the exception
                logger.Error($"Unhandled exception: {ex}");

                // Return a generic error response to the client
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("An unexpected error occurred. Please try again later.");
            }
        }
    }

    public static class ErrorHandlingExtensions
    {
        public static IApplicationBuilder UseErrorHandling(this IApplicationBuilder app)
        {
            return app.UseMiddleware<ErrorHandlingMiddleware>();
        }
    }
}