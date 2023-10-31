using NrExtras.JwtToken_Helper;
using NrExtras.Logger;
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

    public TokenUtility(AppDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
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
            NrExtras.Logger.Logger.WriteToLog("Failed to extract email from token. Err: " + ex, NrExtras.Logger.Logger.LogLevel.Error);
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
            Logger.WriteToLog(ex);
        }

        return false;
    }
}