using System.ComponentModel.DataAnnotations;

namespace Computer_Security_2FA.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        public string? TwoFactorSecret { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;

        public DateTime? LockoutEndUtc { get; set; }

        public bool IsTwoFactorEnabled { get; set; } = true;
    }
}