using Microsoft.EntityFrameworkCore;
using WebApi.Models;

namespace WebApi.Services
{
    /// <summary>
    /// This service is incharge of reset passwords tokens so it would be single use tokens
    /// </summary>
    public class PasswordResetTokenService : IPasswordResetTokenService
    {
        private readonly AppDbContext _context;
        private readonly TokenUtility _tokenUtility;
        private readonly UserService _userService;

        public PasswordResetTokenService(AppDbContext context, TokenUtility tokenUtility, UserService userService)
        {
            _context = context;
            _tokenUtility = tokenUtility;
            _userService = userService;
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
                NrExtras.Logger.Logger.WriteToLog(ex);
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
                .FirstOrDefaultAsync(t => t.UserId == userId && t.Token == token && t.Expiration > DateTime.UtcNow && t.Used == false);

            return validToken != null;
        }

        public async Task MarkTokenAsUsedAsync(string userId, string token)
        {
            var tokenToMark = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == userId && t.Token == token);

            if (tokenToMark != null)
            {
                // Mark the token as used
                tokenToMark.Used = true;
                await _context.SaveChangesAsync();
            }
        }

        public async Task RemovePasswordResetTokenAsync(string userId, string token)
        {
            var tokenToRemove = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == userId && t.Token == token);

            if (tokenToRemove != null)
            {
                _context.PasswordResetTokens.Remove(tokenToRemove);
                await _context.SaveChangesAsync();
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