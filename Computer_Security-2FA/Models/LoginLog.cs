using System.ComponentModel.DataAnnotations;

namespace Computer_Security_2FA.Models
{
    public class LoginLog
    {
        [Key]
        public int Id { get; set; }

        public int? UserId { get; set; }

        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        public DateTime AttemptTimeUtc { get; set; } = DateTime.UtcNow;

        [Required]
        public bool IsSuccess { get; set; }

        [Required]
        public string EventType { get; set; } = string.Empty;
        // Examples:
        // PasswordSuccess
        // PasswordFailed
        // TwoFactorSuccess
        // TwoFactorFailed
        // LockedOut
        // RememberedDeviceLogin

        public string? FailureReason { get; set; }

        public string? IpAddress { get; set; }

        public string? UserAgent { get; set; }

        public bool RememberDeviceUsed { get; set; }
    }
}