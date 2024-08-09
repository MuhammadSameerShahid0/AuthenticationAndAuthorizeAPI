namespace AuthAndAuthorAPI.DTO
{
    public class UserDTO
    {
        public required string UserName { get; set; }
        public required string Passward { get; set; } = string.Empty;
    }
}
