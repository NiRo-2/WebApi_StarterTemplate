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
    }
}