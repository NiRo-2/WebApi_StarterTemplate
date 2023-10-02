using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using WebApi;

/// <summary>
/// Token helper service
/// </summary>
public class TokenUtility
{
    public TokenUtility()
    {}

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
            NrExtras.Logger.Logger.WriteToLog("Failed to extract email from token. Err: " +ex,NrExtras.Logger.Logger.LogLevel.Error);
        }

        // Return an empty string if the email couldn't be extracted or an error occurred
        return string.Empty;
    }
}