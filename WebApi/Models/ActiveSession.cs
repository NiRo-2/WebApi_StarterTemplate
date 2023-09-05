using System.ComponentModel.DataAnnotations;

namespace WebApi.Models
{
    public class ActiveSession
    {
        [Key]
        public string? Id { get; set; }

        [Required]
        public string? token { get; set; }

        [Required]
        public string? UserId { get; set; }

        public DateTime SignInDate { get; set; } = DateTime.UtcNow; // Default value is the current UTC time
    }
}