using NrExtras.JwtToken_Helper;
using System.IdentityModel.Tokens.Jwt;
using WebApi;
using static WebApi.ConfigClassesDefinitions;

/// <summary>
/// Token helper service
/// </summary>
public class TokenUtility
{
    private readonly AppDbContext _context;
    private IConfiguration _configuration;
    public readonly ILogger<TokenUtility> _logger;

    public TokenUtility(AppDbContext context, IConfiguration configuration, ILogger<TokenUtility> logger)
    {
        _context = context;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Extract email from token
    /// </summary>
    /// <param name="token">token</param>
    /// <returns>found email address</returns>
    public string ExtractUserEmailFromToken(string token)
    {
        try
        {
            // Assuming you're using JWT tokens
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            if (jwtToken != null && jwtToken.Claims != null)
            {
                // Find the claim with type "email" (adjust this to match your token's claim)
                var emailClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "email");

                if (emailClaim != null)
                {
                    // Extract the email from the claim
                    return emailClaim.Value;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to extract email from token. Err: " + ex, ex);
        }

        // Return an empty string if the email couldn't be extracted or an error occurred
        return string.Empty;
    }

    /// <summary>
    /// Validate token
    /// </summary>
    /// <param name="token">token</param>
    /// <returns>true if valid, false otherwise</returns>
    public bool IsValidToken(string token)
    {
        try
        {
            //get all values from appsettings
            JwtConfig jwtConfig = _configuration.GetSection("JWT").Get<JwtConfig>();
            //validate using jwtTokenHelper
            return JwtToken_Helper.ValidateCurrentToken(NrExtras.EncryptionHelper.EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtTokenSecret_HashedSecnret), jwtConfig.Issuer, jwtConfig.Audience, token);
        }
        catch (Exception ex)
        {
            // Log any exceptions during token validation
            _logger.LogError(ex.Message, ex);
        }

        return false;
    }

    /// <summary>
    /// Check if token exists in the active sessions
    /// </summary>
    /// <param name="token">token</param>
    /// <returns>true if exists, false otherwise</returns>
    public bool IsTokenExistsInActiveSessions(string? token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        var activeSession = _context.ActiveSessions.FirstOrDefault(s => s.token == token);

        // Check if the active session exists
        return activeSession != null;
    }

    /// <summary>
    /// Ensure access token is valid - check in token exists in active sessions and if it's valid
    /// </summary>
    /// <param name="token">token</param>
    /// <returns>true if token is logged in, false otherwise</returns>
    public bool IsValidAccessToken(string? token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        return (IsTokenExistsInActiveSessions(token) && IsValidToken(token));
    }
}