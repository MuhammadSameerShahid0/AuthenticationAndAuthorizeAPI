namespace AuthAndAuthorAPI.Models
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] PasswardHash { get; set; } 
        public byte[] PasswardSalt { get; set; }
        public string RefreshToken { get; set; }
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}
