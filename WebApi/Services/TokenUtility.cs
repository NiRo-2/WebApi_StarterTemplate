using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using WebApi;

public class TokenUtility
{
    private readonly UserService _userService;

    public TokenUtility(UserService userService)
    {
        _userService = userService;
    }

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

    //public async Task<string?> GetUserIdByEmailAsync(string email)
    //{
    //    var user = await _userService.GetUserByEmailAsync(email);

    //    // Check if the user was found
    //    if (user != null)
    //        return user.Id; // Assuming the user object has an "Id" property

    //    // Return null if the user was not found
    //    return null;
    //}
}