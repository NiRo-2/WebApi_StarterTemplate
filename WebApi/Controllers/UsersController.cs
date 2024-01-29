using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NrExtras.EmailHelper;
using NrExtras.EncryptionHelper;
using NrExtras.Logger;
using NrExtras.PassHash_Helper;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApi.Models;
using WebApi.Services;

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
        private readonly IPasswordResetTokenService _passwordResetTokenService;

        public UsersController(IConfiguration configuration, AppDbContext context, UserService userService, IPasswordResetTokenService passwordResetTokenService)
        {
            _context = context;
            _configuration = configuration;
            _userService = userService;
            _passwordResetTokenService = passwordResetTokenService;
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

                    //last login should be null - make sure of it
                    user.LastLoginDate = null;

                    //validate pass
                    if (!Models.User.IsStrongPassword(user.Password))
                        return BadRequest("Password must include at least one digit and one char");

                    // Hash the password
                    user.Password = PassHash_Helper.HashPassword(user.Password);

                    //add user and update db
                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();

                    // Generate verification email and send it
                    string verificationToken = GenerateEmailVerificationToken(user.Email, EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtTokenSecret_HashedSecnret), TimeSpan.FromHours(Convert.ToDouble(_configuration["JWT:TokenExpirationHours"])));
                    string baseUrl = $"{Request.Scheme}://{Request.Host}";

                    // Send verification email with the verificationLink
                    sendEmailConfirmation(user.Email, baseUrl, verificationToken);

                    //Done
                    Logger.WriteToLog($"{user.Email} Registered (still waiting for email verification)");
                    return Ok("Registration successful.");
                }

                return BadRequest(ModelState);
            }
            catch (Exception ex)
            {
                Logger.WriteToLog(ex);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while processing your request.");
            }
        }

        /// <summary>
        /// Send email confirmation email
        /// </summary>
        /// <param name="email">to whom</param>
        /// <param name="baseUrl">app base url</param>
        /// <param name="verificationToken">verification token</param>
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
        /// Generate email verify token(encrypted)
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
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            //encrypt and base64 token before sending it
            string encryptedToken = tokenHandler.WriteToken(token);
            encryptedToken = EncryptionHelper.EncryptKey(encryptedToken);
            encryptedToken = NrExtras.StringsHelper.StringsHelper.ToBase64(encryptedToken);

            return encryptedToken;
        }

        /// <summary>
        /// Verify email controller get method
        /// </summary>
        /// <param name="token">verify token (encrypted)</param>
        /// <returns></returns>
        [HttpGet("VerifyEmail")]
        public async Task<IActionResult> VerifyEmail(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token))
                    return BadRequest("Invalid verification token.");

                //decrypt from base64 and decrypt the encrypted token before validating it
                try
                {
                    token = NrExtras.StringsHelper.StringsHelper.FromBase64(token);
                    token = EncryptionHelper.DecryptKey(token);
                }
                catch (Exception ex)
                {
                    throw new Exception("Error decrypting token. Err: " + ex);
                }

                // Validate and decode the token
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtTokenSecret_HashedSecnret));

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

        /// <summary>
        /// Forgot password - send email with password reset link
        /// </summary>
        /// <param name="model">ForgotPasswordRequest holding email</param>
        /// <returns></returns>
        [EnableCors("Cors_AllowOrigin_SpecificAddress")]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest model)
        {
            var user = await _userService.GetUserByEmailAsync(model.Email);
            if (user == null)// User not found, return a generic message to avoid information leakage
                return Ok("Password reset request sent if the email exists.");

            // Generate a password reset token using JWT
            var secretKey = EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtTokenSecret_HashedSecnret);

            // Read the token expiration time from appsettings
            var tokenLifetimeMinutes = _configuration.GetValue<int>("JWT:PasswordResetTokenExpirationMinutes");
            var tokenLifetime = TimeSpan.FromMinutes(tokenLifetimeMinutes);

            // Generate the password reset token
            var token = GeneratePasswordResetToken(user.Id, user.Email, secretKey, tokenLifetime);

            //convert to base64 for safe passage
            token = NrExtras.StringsHelper.StringsHelper.ToBase64(token);

            // Send the reset password email with the JWT token
            sendForgotPasswordEmail($"{Request.Scheme}://{Request.Host}", user.Email, token);

            // All done
            return Ok("Password reset request sent. Please check your email.");
        }

        /// <summary>
        /// Generate encrypted password reset jwt
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="userEmail">user email</param>
        /// <param name="secretKey">jwt secret key</param>
        /// <param name="tokenLifetime">jwt expiration</param>
        /// <returns>encypted (to local machine) jwt</returns>
        private string GeneratePasswordResetToken(string userId, string userEmail, string secretKey, TimeSpan tokenLifetime)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.Email, userEmail),
            new Claim("reset", "true") // Custom claim to indicate it's a reset token
        }),
                Expires = DateTime.UtcNow.Add(tokenLifetime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512),
                Issuer = _configuration["JWT:Issuer"], // Get issuer from app settings
                Audience = _configuration["JWT:Audience"] // Get audience from app settings
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            // Save the token in the database with Used = false
            var tokenString = tokenHandler.WriteToken(token);
            _passwordResetTokenService.CreatePasswordResetTokenAsync(userId, tokenString, DateTime.UtcNow.Add(tokenLifetime));

            //encrypt token before sending to user
            tokenString = EncryptionHelper.EncryptKey(tokenString);

            return tokenString;
        }

        /// <summary>
        /// Send forgot password email
        /// </summary>
        /// <param name="email">to whom</param>
        /// <param name="baseUrl">app base url</param>
        /// <param name="token">reset token</param>
        private void sendForgotPasswordEmail(string baseUrl, string email, string token)
        {
            //create reset password page which recieve token and ask the user to choose new password
            string resetPasswordLink = $"{baseUrl}/ResetPassword?token={token}";

            //create subject and body
            string emailSubject = "Password Reset Request";
            string emailBody = $"To reset your password, {NrExtras.Html_Helper.Html_Helper.GetHyperLink(resetPasswordLink, "Click Here")}";

            //send reset password link
            Logger.WriteToLog($"Send reset password link to {email}");
            EmailHelper.sendEmail(_configuration["EmailSettings:FromAddress"], EncryptionHelper.DecryptKey(GlobalDynamicSettings.EmailHashedPass), _configuration["EmailSettings:mailServer"], int.Parse(_configuration["EmailSettings:mailServerPort"]), new List<string>() { email }, null, null, emailSubject, emailBody);
        }

        /// <summary>
        /// Password update. *pay attention that token is being decrypted in the Razor page*
        /// </summary>
        /// <param name="model">model holding token, email and new password</param>
        /// <returns>Ok if all good, BadRequest if otherwise</returns>
        [EnableCors("Cors_AllowOrigin_SpecificAddress")]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
        {
            try
            {
                var user = await _userService.GetUserByEmailAsync(model.Email);
                if (user == null)
                    return Ok("Password reset request sent if the email exists.");

                // Verify the provided token
                if (string.IsNullOrEmpty(model.Token))
                    return BadRequest("Token is required for password reset.");

                // Check if the token has already been used
                var tokenValid = await _passwordResetTokenService.VerifyPasswordResetTokenAsync(user.Id, model.Token);
                if (!tokenValid)
                    return BadRequest("Invalid or expired token.");

                //check for valid pass
                if (!Models.User.IsStrongPassword(model.NewPassword)) return BadRequest("Password must include at least one digit and one char");

                // Mark the token as used
                await _passwordResetTokenService.MarkTokenAsUsedAsync(user.Id, model.Token);

                // Reset the user's password
                bool passwordResetResult = await _userService.UpdateUserPasswordAsync(user.Id, model.NewPassword);
                if (passwordResetResult)
                {
                    //send password reset success email
                    sendResetPasswordSuccessEmail(user.Email);
                    return Ok("Password reset successful.");
                }

                // If we got here, we had an error
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while resetting the password.");
            }
            catch (Exception)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while processing your request.");
            }
        }

        /// <summary>
        /// Send password reset success email
        /// </summary>
        /// <param name="email">user email</param>
        private void sendResetPasswordSuccessEmail(string email)
        {
            //create subject and body
            string emailSubject = "Password Reset success!";
            string emailBody = "Your password has resetted successfuly.";

            //send reset password link
            Logger.WriteToLog($"Send reset password success email to {email}");
            EmailHelper.sendEmail(_configuration["EmailSettings:FromAddress"], EncryptionHelper.DecryptKey(GlobalDynamicSettings.EmailHashedPass), _configuration["EmailSettings:mailServer"], int.Parse(_configuration["EmailSettings:mailServerPort"]), new List<string>() { email }, null, null, emailSubject, emailBody);
        }
    }
}