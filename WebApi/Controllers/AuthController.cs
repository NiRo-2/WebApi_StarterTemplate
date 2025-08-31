using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NrExtras.EncryptionHelper;
using NrExtras.Google;
using NrExtras.NetAddressUtils;
using NrExtras.PassHash_Helper;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApi.Models;
using WebApi.Services;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _context;
        private readonly UserService _userService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IConfiguration configuration, AppDbContext context, UserService userService, ILogger<AuthController> logger)
        {
            _configuration = configuration;
            _context = context;
            _userService = userService;
            _logger = logger;
        }

        #region Login
        /// <summary>
        /// Login
        /// </summary>
        /// <param name="model">login model holder email and pass (in case enable - also reCaptcha</param>
        /// <returns>token</returns>
        [EnableCors("Cors_AllowOrigin_SpecificAddress")]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest("Invalid request");

                // Verify the reCAPTCHA token
                if (_configuration.GetValue<bool>("reCaptcha:Active"))
                {
                    // Check if reCAPTCHA v2 is enabled and the token is provided. if not provided, return BadRequest
                    if (string.IsNullOrEmpty(model.recaptchaToken_v3))
                    {
                        _logger.LogWarning($"Host: {IpHostData.GetHostDataFromHttpContext(HttpContext)} Invalid login attempt for Email: {model.email} reCAPTCHA v3 token not provided.");
                        return BadRequest("reCAPTCHA v3 token is required.");
                    }

                    // Validate the reCAPTCHA v3 token using the secret key
                    var result = await Google_reCaptcha_Helper.ReCaptcha_v3.ValidateRecaptchaDetailedAsync(model.recaptchaToken_v3 ?? string.Empty, _configuration["reCaptcha:V3:Secret"] ?? string.Empty);
                    // V3 failed
                    if (!result.Success)
                    {
                        _logger.LogWarning($"Host: {IpHostData.GetHostDataFromHttpContext(HttpContext)} Invalid login attempt for Email: {model.email} reCAPTCHA v3 failed. Score={result.Score}, Error={result.Error}");

                        // If reCAPTCHA validation fails, return a 428 Precondition Required status code to indicate that the client should retry with a reCAPTCHA fallback (if exist)
                        return StatusCode(StatusCodes.Status428PreconditionRequired, new
                        {
                            recaptchaFallbackRequired = true,
                            reason = result.Error ?? "Low score or validation failed"
                        });
                    }
                }

                var user = await _userService.GetUserByEmailAsync(model.email);
                if (user == null || !PassHash_Helper.VerifyHashVsPass(model.password, user.Password))
                {
                    _logger.LogWarning($"Invalid login attempt for Email: {model.email}");
                    return Unauthorized("Invalid credentials");
                }

                //validating email confirmed
                if (user.EmailConfirmed == 0)
                {
                    _logger.LogInformation($"Success login but email not confirmed for Email: {model.email}");
                    return Unauthorized("Email not confirmed");
                }

                // Valid user, password and email confirmed
                _logger.LogInformation($"Successful login for Email: {model.email}");
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
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during login.");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while processing your request.");
            }
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
                string? authorizationHeader = HttpContext.Request.Headers["Authorization"];
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
                                _logger.LogInformation($"Successful logout for Email: {userEmailClaim.Value}");
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