﻿using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NLog;
using NLog.Web;
using NrExtras.PassHash_Helper;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApi.Models;

namespace WebApi.Services
{
    /// <summary>
    /// This service is incharge of reset passwords tokens so it would be single use tokens
    /// </summary>
    public class PasswordResetTokenService : IPasswordResetTokenService
    {
        private Logger logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
        private readonly AppDbContext _context;
        private readonly TokenUtility _tokenUtility;
        private readonly UserService _userService;
        private readonly IConfiguration _configuration;

        public PasswordResetTokenService(AppDbContext context, TokenUtility tokenUtility, UserService userService, IConfiguration configuration)
        {
            _context = context;
            _tokenUtility = tokenUtility;
            _userService = userService;
            _configuration = configuration;
        }

        /// <summary>
        /// Remove expired tokens from db
        /// </summary>
        /// <returns></returns>
        public async Task RemoveExpiredTokensAsync()
        {
            // Find all expired tokens
            var expiredTokens = await _context.PasswordResetTokens
                .Where(t => t.Expiration <= DateTime.UtcNow)
                .ToListAsync();

            if (expiredTokens.Any())
            {
                // Remove the expired tokens from the database
                _context.PasswordResetTokens.RemoveRange(expiredTokens);
                await _context.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Create password reset token object in db
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="token">used token</param>
        /// <param name="expiration">token expiration</param>
        /// <returns></returns>
        public async Task CreatePasswordResetTokenAsync(string userId, string token, DateTime expiration)
        {
            var existingToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == userId && t.Expiration > DateTime.UtcNow);

            //hash token
            token = PassHash_Helper.HashPassword(token);

            if (existingToken != null)
            {
                // If a valid token exists, update it with the new token, expiration, and reset Used to false
                existingToken.Token = token;
                existingToken.Expiration = expiration;
                existingToken.Used = false; // Reset Used to false
            }
            else
            {
                // Otherwise, create a new token
                var newToken = new PasswordResetToken
                {
                    UserId = userId,
                    Token = token,
                    Expiration = expiration,
                    Used = false // Set Used to false for the new token
                };

                _context.PasswordResetTokens.Add(newToken);
            }

            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Verify token
        /// </summary>
        /// <param name="token">token</param>
        /// <returns></returns>
        public async Task<bool> VerifyPasswordResetTokenAsync(string token)
        {
            try
            {
                // Extract user email from the token (You'll need a method to do this)
                string userEmail = _tokenUtility.ExtractUserEmailFromToken(token);

                if (!string.IsNullOrEmpty(userEmail))
                {
                    // Get the userId based on the userEmail
                    User? user = await _userService.GetUserByEmailAsync(userEmail);

                    if (user != null)
                        return await VerifyPasswordResetTokenAsync(user.Id, token);
                }

                return false;
            }
            catch (Exception ex)
            {
                logger.Error(ex);
                return false;
            }
        }

        /// <summary>
        /// Verify token
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="token">token</param>
        /// <returns></returns>
        public async Task<bool> VerifyPasswordResetTokenAsync(string userId, string token)
        {
            var validToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == userId && t.Expiration > DateTime.UtcNow && t.Used == false);

            if (validToken != null)
            {
                // Validate received token against the stored hashed token in the database
                if (PassHash_Helper.VerifyHashVsPass(token, validToken.Token))
                {
                    var tokenHandler = new JwtSecurityTokenHandler();

                    // Configure token validation parameters
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidIssuer = _configuration["JWT:Issuer"],
                        ValidAudience = _configuration["JWT:Audience"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(NrExtras.EncryptionHelper.EncryptionHelper.DecryptKey(GlobalDynamicSettings.JwtTokenSecret_HashedSecnret)))
                    };

                    // Validate the token using the validation parameters
                    SecurityToken validatedToken;
                    var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);

                    // Check the "reset" claim
                    var resetClaim = (principal.Identity as ClaimsIdentity)?.FindFirst("reset");
                    if (resetClaim != null && resetClaim.Value == "true")
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// mark token as used after user used it
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="token">token</param>
        /// <returns></returns>
        public async Task MarkTokenAsUsedAsync(string userId, string token)
        {
            var tokenToMark = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == userId);

            if (tokenToMark != null)
            {
                //validate recieved token equal the saved hashed value in db
                if (PassHash_Helper.VerifyHashVsPass(token, tokenToMark.Token))
                {
                    // Mark the token as used
                    tokenToMark.Used = true;
                    await _context.SaveChangesAsync();
                }
                else //incase hashed token isn't the same as found input token
                    throw new Exception("Invalid token");
            }
        }

        /// <summary>
        /// remove password reset token from db
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="token">token</param>
        /// <returns></returns>
        public async Task RemovePasswordResetTokenAsync(string userId, string token)
        {
            var tokenToRemove = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == userId);

            if (tokenToRemove != null)
            {
                //validate recieved token equal the saved hashed value in db
                if (PassHash_Helper.VerifyHashVsPass(token, tokenToRemove.Token))
                {
                    _context.PasswordResetTokens.Remove(tokenToRemove);
                    await _context.SaveChangesAsync();
                }
                else //incase hashed token isn't the same as found input token
                    throw new Exception("Invalid token");
            }
        }

        /// <summary>
        /// Extract email from token
        /// </summary>
        /// <param name="token">token</param>
        /// <returns>found email address</returns>
        public Task<string> ExtractEmailFromToken(string token)
        {
            return Task.FromResult(_tokenUtility.ExtractUserEmailFromToken(token));
        }
    }
}