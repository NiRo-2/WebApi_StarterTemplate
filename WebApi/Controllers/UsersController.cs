using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NrExtras;
using NrExtras.EmailHelper;
using NrExtras.EncryptionHelper;
using NrExtras.Logger;
using NrExtras.PassHash_Helper;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApi.Models;

namespace WebApi.Controllers
{
    //This controller handles user registration
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _context;
        private readonly UserService _userService;

        public UsersController(IConfiguration configuration, AppDbContext context, UserService userService)
        {
            _context = context;
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            return await _context.Users.ToListAsync();
        }

        // POST: api/users/register
        [EnableCors("Cors_AllowOrigin_SpecificAddress")]
        [HttpPost("register")]
        public async Task<IActionResult> Register(User user)
        {
            try
            {
                // Check email validity before any other validation
                if (!EmailHelper.IsValidEmail(user.Email))
                    return BadRequest("Invalid email address format.");

                if (ModelState.IsValid)
                {
                    // Check if the username or email is already registered
                    if (await _context.Users.AnyAsync(u => u.UserName == user.UserName || u.Email == user.Email))
                        return BadRequest("Username or email is already taken.");

                    // Hash the password
                    user.Password = PassHash_Helper.HashPassword(user.Password);

                    //add user and update db
                    _context.Users.Add(user);
                    //_context.SaveChanges();
                    await _context.SaveChangesAsync();

                    // Generate verification email and send it
                    string verificationToken = GenerateEmailVerificationToken(user.Email, EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtToken_HashedSecnret), TimeSpan.FromHours(Convert.ToDouble(_configuration["JWT:TokenExpirationHours"])));
                    string baseUrl = $"{Request.Scheme}://{Request.Host}";

                    // Send verification email with the verificationLink
                    sendEmailConfirmation(user.Email, baseUrl, verificationToken);

                    return Ok("Registration successful.");
                }

                return BadRequest(ModelState);
            }
            catch (Exception)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while processing your request.");
            }
        }

        /// <summary>
        /// Send email confirmation email
        /// </summary>
        /// <param name="email">to who</param>
        private void sendEmailConfirmation(string email, string baseUrl, string verificationToken)

        {
            Logger.WriteToLog($"Send email confirmation to {email}");

            //get expire minute/hours
            TimeSpan linkExpiration = TimeSpan.FromHours(Convert.ToDouble(_configuration["JWT:TokenExpirationHours"]));
            string formattedExpiration = linkExpiration.TotalHours < 1 ? $"{linkExpiration.TotalMinutes} minutes" : $"{linkExpiration.TotalHours} hours";
            string verificationLink = $"{baseUrl}/api/Users/VerifyEmail?token={verificationToken}";

            //setting subjet and body
            string subject = "Email Verification";
            string body = $"Click <a href='{verificationLink}'>here</a> to verify your email. This link will expire after {formattedExpiration}.";

            //send email
            EmailHelper.sendEmail(_configuration["EmailSettings:FromAddress"], EncryptionHelper.DecryptKey(GlobalDynamicSettings.EmailHashedPass), _configuration["EmailSettings:mailServer"], int.Parse(_configuration["EmailSettings:mailServerPort"]), new List<string>() { email }, null, null, subject, body);
        }

        /// <summary>
        /// Generate email verify token
        /// </summary>
        /// <param name="userEmail"></param>
        /// <param name="secretKey"></param>
        /// <param name="tokenLifetime"></param>
        /// <returns>jwt</returns>
        private string GenerateEmailVerificationToken(string userEmail, string secretKey, TimeSpan tokenLifetime)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.Email, userEmail)
        }),
                Expires = DateTime.UtcNow.Add(tokenLifetime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// Verify email controller get method
        /// </summary>
        /// <param name="token">verify token</param>
        /// <returns></returns>
        [HttpGet("VerifyEmail")]
        public async Task<IActionResult> VerifyEmail(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token))
                    return BadRequest("Invalid verification token.");

                // Validate and decode the token
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtToken_HashedSecnret));

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };

                ClaimsPrincipal claimsPrincipal;
                try
                {
                    claimsPrincipal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                }
                catch (Exception)
                {
                    return BadRequest("Invalid verification token.");
                }

                // Extract user email from claims
                var userEmailClaim = claimsPrincipal.FindFirst(ClaimTypes.Email)?.Value;
                if (string.IsNullOrEmpty(userEmailClaim))
                    return BadRequest("Invalid verification token.");

                // Update user's email confirmation status
                if (await _userService.UpdateUserEmailConfirmationStatusAsync(userEmailClaim))
                {
                    Logger.WriteToLog($"Email verification successful for email {userEmailClaim}");
                    return Ok("Email verification successful.");
                }

                return BadRequest("Invalid verification token.");
            }
            catch (Exception)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while processing your request.");
            }
        }
    }
}