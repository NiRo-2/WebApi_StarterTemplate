using Microsoft.EntityFrameworkCore;
using NrExtras.PassHash_Helper;
using System.Text.RegularExpressions;
using WebApi.Models;

namespace WebApi.Services
{
    /// <summary>
    /// User service for user-related operations
    /// </summary>
    public class UserService
    {
        private readonly ILogger<UserService> _logger;
        private readonly AppDbContext _context;

        public UserService(AppDbContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// Get user by email
        /// </summary>
        /// <param name="email"></param>
        /// <returns>Found user or null</returns>
        public async Task<User?> GetUserByEmailAsync(string email)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Update user email confirmation as confirmed
        /// </summary>
        /// <param name="email">email address</param>
        /// <returns>true on success, false otherwise</returns>
        public async Task<bool> UpdateUserEmailConfirmationStatusAsync(string email)
        {
            try
            {
                var user = await GetUserByEmailAsync(email);
                if (user != null)
                {
                    user.EmailConfirmed = 1;
                    await _context.SaveChangesAsync();
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Update the user password
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="newPassword">new password</param>
        /// <returns>true on successes, false otherwise</returns>
        public async Task<bool> UpdateUserPasswordAsync(string userId, string newPassword)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId);
                if (user != null)
                {
                    //check for valid pass
                    if (!User.IsStrongPassword(newPassword)) return false;

                    // Update the user's password
                    user.Password = PassHash_Helper.HashPassword(newPassword);
                    await _context.SaveChangesAsync();
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Validates if a given string is a valid username.
        /// A valid username contains only alphanumeric characters, underscores, and dots,
        /// and must be between 3 and 20 characters long.
        /// </summary>
        /// <param name="username">The username string to validate.</param>
        /// <returns>True if the username is valid; otherwise, false.</returns>
        public bool IsValidUsername(string username)
        {
            // Null or empty strings are not valid usernames
            if (string.IsNullOrEmpty(username))
                return false;

            // Define a regex pattern for a valid username
            string pattern = "^[a-zA-Z0-9_.]{3,20}$";

            // Use Regex to match the pattern
            return Regex.IsMatch(username, pattern);
        }
    }
}