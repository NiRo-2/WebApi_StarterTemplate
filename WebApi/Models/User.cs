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
        [MinLength(5, ErrorMessage = "Password must be at least 5 characters long.")]
        public required string Password { get; set; }

        public int EmailConfirmed { get; set; }

        public DateTime RegistrationDate { get; set; }
    }
}