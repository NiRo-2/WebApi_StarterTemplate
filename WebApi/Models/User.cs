using System.ComponentModel.DataAnnotations;

namespace WebApi.Models
{
    public class User
    {
        [Key]
        public string Id { get; set; } = "";

        [Required(ErrorMessage = "Invalid user name")]
        public required string UserName { get; set; }

        [Required]
        [EmailAddress(ErrorMessage = "Invalid email address format.")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Invalid password")]
        [MinLength(GlobalDynamicSettings.UserMinPassLength, ErrorMessage = "Invalid password length")]
        public required string Password { get; set; }

        public int EmailConfirmed { get; set; }

        public DateTime RegistrationDate { get; set; }

        public DateTime? LastLoginDate { get; set; }

        /// <summary>
        /// Verify pass is strong. min chars and at least 1 digit and 1 char
        /// </summary>
        /// <param name="password"></param>
        /// <returns>true if valid, false otherwise</returns>
        public static bool IsStrongPassword(string password)
        {
            return password.Length >= GlobalDynamicSettings.UserMinPassLength && password.Any(char.IsLetter) && password.Any(char.IsDigit);
        }
    }
}