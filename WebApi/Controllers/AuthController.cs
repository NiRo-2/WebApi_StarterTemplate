using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NrExtras.EncryptionHelper;
using NrExtras.Logger;
using NrExtras.PassHash_Helper;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApi.Models;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _context;
        private readonly UserService _userService;

        public AuthController(IConfiguration configuration, AppDbContext context, UserService userService)
        {
            _configuration = configuration;
            _context = context;
            _userService = userService;
        }

        #region Login
        /// <summary>
        /// Login
        /// </summary>
        /// <param name="model">login model holder email and pass</param>
        /// <returns>token</returns>
        [EnableCors("Cors_AllowOrigin_SpecificAddress")]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid request");

            var user = await _userService.GetUserByEmailAsync(model.email);
            if (user == null || !PassHash_Helper.VerifyHashVsPass(model.password, user.Password))
            {
                Logger.WriteToLog($"Invalid login attempt for Email: {model.email}");
                return Unauthorized("Invalid credentials");
            }

            //validating email confirmed
            if (user.EmailConfirmed == 0)
            {
                Logger.WriteToLog($"Success login but email not confirmed for Email: {model.email}");
                return Unauthorized("Email not confirmed");
            }

            // Valid user, password and email confirmed
            Logger.WriteToLog($"Successful login for Email: {model.email}");
            // Update the LastLoginDate property and save the changes to the database
            user.LastLoginDate = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            //generate token
            var token = GenerateJwtToken(user);

            // Create an active session
            await CreateActiveSessionAsync(user, token);

            //return encrypted token to user
            return Ok(new { Token = EncryptionHelper.EncryptKey(token) });
        }

        /// <summary>
        /// Add new active session to activeSessions
        /// </summary>
        /// <param name="user"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        private async Task CreateActiveSessionAsync(User user, string token)
        {
            var activeSession = new ActiveSession
            {
                Id = NrExtras.GuidGenerator.GuidGenerator.generateGUID(), // Generate a unique ID for the active session
                UserId = user.Id, // Use the user's ID
                token = token
            };

            _context.ActiveSessions.Add(activeSession);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Generate user token
        /// </summary>
        /// <param name="user">user to generate token to</param>
        /// <returns>return token</returns>
        private string GenerateJwtToken(User user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtTokenSecret_HashedSecnret)));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(Convert.ToDouble(_configuration["JWT:TokenExpirationHours"])),
                signingCredentials: credentials);

            //return token
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        #endregion

        #region Logout
        [EnableCors("Cors_AllowOrigin_SpecificAddress")]
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                // Get the token from the Authorization header
                string authorizationHeader = HttpContext.Request.Headers["Authorization"];
                if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
                    return BadRequest("Invalid authorization header");

                //get token
                string token = EncryptionHelper.DecryptKey(authorizationHeader.Substring("Bearer ".Length));

                //read email out of the token
                var tokenHandler = new JwtSecurityTokenHandler();
                if (tokenHandler.CanReadToken(token))
                {
                    var parsedToken = tokenHandler.ReadJwtToken(token);
                    var userEmailClaim = parsedToken.Claims.FirstOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Sub);

                    //make sure we have email
                    if (userEmailClaim != null)
                    {
                        var userEmail = userEmailClaim.Value;
                        var authenticatedUser = await _userService.GetUserByEmailAsync(userEmail);

                        // Log out the user and delete the active session
                        if (authenticatedUser != null)
                            if (await LogoutAsync(authenticatedUser))
                            {
                                Logger.WriteToLog($"Successful logout for Email: {userEmailClaim.Value}");
                                return Ok("Logout successful.");
                            }
                    }
                }

                //fail
                return BadRequest("Logout failed.");
            }
            catch (Exception)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while processing your request.");
            }
        }

        //do logout
        private async Task<bool> LogoutAsync(User user)
        {
            var activeSession = await _context.ActiveSessions.FirstOrDefaultAsync(s => s.UserId == user.Id);
            if (activeSession != null)
            {
                _context.ActiveSessions.Remove(activeSession);
                await _context.SaveChangesAsync();
                return true;
            }

            return false;
        }
        #endregion
    }
}