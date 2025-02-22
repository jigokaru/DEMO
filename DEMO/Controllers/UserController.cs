using DEMO.Models;
using DEMO.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Net;
using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

namespace DEMO.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        public UserController(ApplicationDbContext context, IConfiguration configuration)
        {
            this._context = context;
            _configuration = configuration;
        }

        [Authorize(Roles = "ADMIN")]
        public IActionResult Index()
        {
            var user = _context.User.ToList();
            return View(user);
        }

        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register(User user)
        {
            if (ModelState.IsValid)
            {
                user.password = BCrypt.Net.BCrypt.HashPassword(user.password);
                if (string.IsNullOrEmpty(user.userRole))
                {
                    user.userRole = "USER";
                }
                user.createAt = DateTime.Now;
                _context.User.Add(user);
                await _context.SaveChangesAsync();
                return RedirectToAction("Login");
            }
            return View(user);
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            var user = await _context.User.FirstOrDefaultAsync(u => u.email == email && u.IsActive == true);
            if (user != null && BCrypt.Net.BCrypt.Verify(password, user.password))
            {
                var token = CreateToken(user, _configuration);
                Response.Cookies.Append("AuthToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true, 
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddMinutes(30)
                });

                _context.Tokens.Add(new Tokens
                {
                    stoken = token,
                    expiresAt = DateTime.UtcNow.AddMinutes(30),
                    token_type = "Bearer",
                    userId = user.userId,
                    User = user
                });
                await _context.SaveChangesAsync();

                if (user.userRole == "ADMIN")
                {
                    return RedirectToAction("Index", "User");
                }
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ViewBag.Error = "Tài khoản của bạn đã bị vô hiệu hóa.";
                return View();
            }
        }



        [Authorize]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("AuthToken");
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public IActionResult DisableUser(int id)
        {
            var user = _context.User.FirstOrDefault(u => u.userId == id);
            if (user != null && user.IsActive)
            {
                user.IsActive = false;
                _context.SaveChanges();
                return Json(new { success = true });
            }
            return Json(new { success = false });
        }



        private string CreateToken(User user, IConfiguration configuration)
        {
            try
            {
                var secretKey = configuration["Jwt:SecretKey"];
                if (string.IsNullOrEmpty(secretKey))
                {
                    throw new ArgumentNullException("Jwt:SecretKey is missing in configuration.");
                }

                var key = Encoding.UTF8.GetBytes(secretKey);

                var claims = new List<Claim>
                {
                     new Claim(ClaimTypes.Email, user.email), 
                     new Claim(ClaimTypes.Role, user.userRole),
                     new Claim("role", user.userRole), 
                     new Claim("accountId", user.userId.ToString())
                };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                // Thêm nickname nếu có
                if (!string.IsNullOrEmpty(user.nickName))
                {
                    claims.Add(new Claim("username", user.nickName));
                    claims.Add(new Claim(ClaimTypes.Name, user.nickName));
                }

                // Tạo token descriptor
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature
                    )
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("An error occurred while creating the token.", ex);
            }
        }


    }
}
