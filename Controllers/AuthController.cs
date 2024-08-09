using AuthAndAuthorAPI.DTO;
using AuthAndAuthorAPI.Models;
using BCrypt.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthAndAuthorAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly RefreshToken _refreshToken;

        public static User user = new User();

        public AuthController(IConfiguration configuration, RefreshToken refreshToken)
        {
            _configuration = configuration;
            _refreshToken = refreshToken;
        }

        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            CreatePasswordHash(request.Passward, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = request.UserName;
            user.PasswardHash = passwordHash;
            user.PasswardSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login(UserDTO login)
        {
            if (user.UserName != login.UserName)
            {
                return BadRequest("UserName Not Found");
            }

            if (!VerifyPasswordHash(login.Passward, user.PasswardHash, user.PasswardSalt))
            { 
                return BadRequest("Invalid Password");
            }

            string token = CreateToken(user);

            var refreshtoken = GenerateRefreshToken();
            SetRefreshToken(refreshtoken);

            return Ok(token);
        }

        [HttpPost("Refresh-Token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var request = Request.Cookies["refreshtoken"];

            if (!user.RefreshToken.Equals(request))
            {
                return Unauthorized("Invalid Token.");
            }
            if(user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token Expired");
            }

            string Token = CreateToken(user);
            var newrefreshtoken = GenerateRefreshToken();
            SetRefreshToken(newrefreshtoken);

            return Ok(Token);
        }
        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Created = DateTime.Now,
                Expires = DateTime.Now.AddDays(1),
            };
            return refreshToken;
        }
        private void SetRefreshToken(RefreshToken newrefreshToken)
        {
            var CookieOptions = new CookieOptions
            {
                Expires = newrefreshToken.Expires
            };
            Response.Cookies.Append("refreshtoken", newrefreshToken.Token , CookieOptions);

            user.RefreshToken = newrefreshToken.Token;
            user.TokenExpires = newrefreshToken.Expires;
            user.TokenCreated = newrefreshToken.Created;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name , user.UserName),
                new Claim(ClaimTypes.Role , "Admin")
            };

            var Key = new SymmetricSecurityKey(
                Encoding
                .UTF8
                .GetBytes(_configuration.GetSection("Appsettings:Token").Value!));

            var creds = new SigningCredentials(Key , SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            
            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
