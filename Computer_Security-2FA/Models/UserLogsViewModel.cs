namespace Computer_Security_2FA.Models
{
    public class UserLogsViewModel
    {
        public string UserName { get; set; } = string.Empty;
        public List<LoginLog> Logs { get; set; } = new();
    }
}