using System.Security.Claims;
using System.Text.Json;
using Computer_Security_2FA.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OtpNet;
using QRCoder;

namespace Computer_Security_2FA.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IDataProtector _protector;
        private readonly PasswordHasher<User> _passwordHasher;

        private const int MaxFailedAttempts = 5;
        private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan RememberDeviceDuration = TimeSpan.FromDays(7);
        private const string RememberDeviceCookieName = "remember_device_token";

        public AuthController(
            ApplicationDbContext context,
            IDataProtectionProvider dataProtectionProvider)
        {
            _context = context;
            _protector = dataProtectionProvider.CreateProtector("RememberDeviceProtector");
    
            _passwordHasher = new PasswordHasher<User>();
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            

            var user = _context.Users.FirstOrDefault(u => u.UserName == model.UserName);

            if (user == null)
            {
                await AddLoginLogAsync(
                    user: null,
                    userName: model.UserName,
                    isSuccess: false,
                    eventType: "PasswordFailed",
                    failureReason: "User not found",
                    rememberDeviceUsed: false);

                ViewBag.Message = "Incorrect username or password!";
                return View(model);
            }

            if (user.LockoutEndUtc.HasValue && user.LockoutEndUtc.Value > DateTime.UtcNow)
            {
                await AddLoginLogAsync(
                    user,
                    user.UserName,
                    false,
                    "LockedOut",
                    $"Locked until {user.LockoutEndUtc:O}",
                    false);

                ViewBag.Message = $"Too many failed attempts. Please wait after{user.LockoutEndUtc.Value.ToLocalTime()}. ";
                return View(model);
            }

            var passwordResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);

            if (passwordResult == PasswordVerificationResult.Failed)
            {
                user.FailedLoginAttempts++;

                if (user.FailedLoginAttempts >= MaxFailedAttempts)
                {
                    user.LockoutEndUtc = DateTime.UtcNow.Add(LockoutDuration);
                    user.FailedLoginAttempts = 0;
                }

                _context.SaveChanges();

                await AddLoginLogAsync(
                    user,
                    user.UserName,
                    false,
                    "PasswordFailed",
                    "Wrong password",
                    false);

                ViewBag.Message = "Incorrect username or password!";
                return View(model);
            }

            if (passwordResult == PasswordVerificationResult.SuccessRehashNeeded)
            {
                user.PasswordHash = _passwordHasher.HashPassword(user, model.Password);
            }

            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            _context.SaveChanges();

            await AddLoginLogAsync(
                user,
                user.UserName,
                true,
                "PasswordSuccess",
                null,
                false);

            if (IsRememberedDeviceValid(user))
            {
                HttpContext.Session.SetString("UserName", user.UserName);

                await AddLoginLogAsync(
                    user,
                    user.UserName,
                    true,
                    "RememberedDeviceLogin",
                    null,
                    true);

                return RedirectToAction("Welcome");
            }

            HttpContext.Session.SetString("Pending2FAUserName", user.UserName);
            HttpContext.Session.SetString("PendingRememberDevice", model.RememberDevice.ToString());

            return RedirectToAction("Verify2FA");
        }

        [HttpGet]
        public IActionResult Verify2FA()
        {
            var userName = HttpContext.Session.GetString("Pending2FAUserName");
            if (string.IsNullOrEmpty(userName))
                return RedirectToAction("Login");

            return View(new Verify2FAViewModel
            {
                UserName = userName,
                RememberDevice = HttpContext.Session.GetString("PendingRememberDevice") == "True"
            });
        }

        [HttpPost]
        public async Task<IActionResult> Verify2FA(Verify2FAViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var sessionUser = HttpContext.Session.GetString("Pending2FAUserName");
            if (string.IsNullOrEmpty(sessionUser) || sessionUser != model.UserName)
                return RedirectToAction("Login");

            var user = _context.Users.FirstOrDefault(u => u.UserName == model.UserName);

            if (user == null)
            {
                ViewBag.Message = "User not found.";
                return RedirectToAction("Login");
            }

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                ViewBag.Message = "2FA is not set up for this user.";
                return RedirectToAction("Login");
            }

            var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
            bool isValid = totp.VerifyTotp(model.Code, out _, new VerificationWindow(2, 2));

            if (!isValid)
            {
                await AddLoginLogAsync(
                    user,
                    user.UserName,
                    false,
                    "TwoFactorFailed",
                    "Wrong TOTP code",
                    false);

                ViewBag.Message = "The verification code is incorrect!";
                return View(model);
            }

            HttpContext.Session.Remove("Pending2FAUserName");
            HttpContext.Session.Remove("PendingRememberDevice");
            HttpContext.Session.SetString("UserName", user.UserName);

            if (model.RememberDevice)
            {
                SetRememberDeviceCookie(user);
            }

            await AddLoginLogAsync(
                user,
                user.UserName,
                true,
                "TwoFactorSuccess",
                null,
                model.RememberDevice);

            return RedirectToAction("Welcome");
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View(new RegisterViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            

            bool userExists = _context.Users.Any(u => u.UserName == model.UserName);
            if (userExists)
            {
                ViewBag.Message = "This username is already registered.";
                return View(model);
            }

            var secretKey = KeyGeneration.GenerateRandomKey(20);
            var base32Secret = Base32Encoding.ToString(secretKey);

            var user = new User
            {
                UserName = model.UserName,
                TwoFactorSecret = base32Secret,
                IsTwoFactorEnabled = true
            };

            user.PasswordHash = _passwordHasher.HashPassword(user, model.Password);

            _context.Users.Add(user);
            _context.SaveChanges();

            string issuer = "MyApp";
            string otpauth = $"otpauth://totp/{issuer}:{user.UserName}?secret={base32Secret}&issuer={issuer}";

            using var qrGenerator = new QRCodeGenerator();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(otpauth, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new PngByteQRCode(qrCodeData);
            string base64Qr = Convert.ToBase64String(qrCode.GetGraphic(20));

            ViewBag.QR = base64Qr;
            ViewBag.Secret = base32Secret;
            ViewBag.UserName = user.UserName;

            return View("Setup2FA");
        }

        [HttpPost]
        public IActionResult ConfirmSetup(string userName, string code)
        {
            var user = _context.Users.FirstOrDefault(u => u.UserName == userName);

            if (user == null)
                return Content("User not found.");

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
                return Content("2FA secret not found.");

            var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
            bool isValid = totp.VerifyTotp(code, out _, new VerificationWindow(2, 2));

            if (!isValid)
            {
                string issuer = "MyApp";
                string otpauth = $"otpauth://totp/{issuer}:{user.UserName}?secret={user.TwoFactorSecret}&issuer={issuer}";

                using var qrGenerator = new QRCodeGenerator();
                QRCodeData qrCodeData = qrGenerator.CreateQrCode(otpauth, QRCodeGenerator.ECCLevel.Q);
                var qrCode = new PngByteQRCode(qrCodeData);
                string base64Qr = Convert.ToBase64String(qrCode.GetGraphic(20));

                ViewBag.QR = base64Qr;
                ViewBag.Secret = user.TwoFactorSecret;
                ViewBag.UserName = user.UserName;
                ViewBag.Message = "The code is incorrect. Please try again.";

                return View("Setup2FA");
            }

            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult Welcome()
        {
            var userName = HttpContext.Session.GetString("UserName");

            if (string.IsNullOrEmpty(userName))
                return RedirectToAction("Login");

            var logs = _context.LoginLogs
                .Where(x => x.UserName == userName)
                .OrderByDescending(x => x.AttemptTimeUtc)
                .Take(10)
                .ToList();

            var model = new UserLogsViewModel
            {
                UserName = userName,
                Logs = logs
            };

            return View(model);
        }

        [HttpGet]
        public IActionResult Logout()
        {
            
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        private bool IsRememberedDeviceValid(User user)
        {
            if (!Request.Cookies.TryGetValue(RememberDeviceCookieName, out var protectedValue))
                return false;

            try
            {
                var raw = _protector.Unprotect(protectedValue);
                var parts = raw.Split('|');

                if (parts.Length != 3)
                    return false;

                var userId = parts[0];
                var userName = parts[1];
                var expiresUtc = DateTime.Parse(parts[2]);

                if (expiresUtc < DateTime.UtcNow)
                    return false;

                return userId == user.Id.ToString() && userName == user.UserName;
            }
            catch
            {
                return false;
            }
        }

        private void SetRememberDeviceCookie(User user)
        {
            var expiresUtc = DateTime.UtcNow.Add(RememberDeviceDuration);
            var raw = $"{user.Id}|{user.UserName}|{expiresUtc:O}";
            var protectedValue = _protector.Protect(raw);

            Response.Cookies.Append(RememberDeviceCookieName, protectedValue, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                IsEssential = true,
                SameSite = SameSiteMode.Strict,
                Expires = expiresUtc
            });
        }

        private async Task AddLoginLogAsync(
            User? user,
            string userName,
            bool isSuccess,
            string eventType,
            string? failureReason,
            bool rememberDeviceUsed)
        {
            var log = new LoginLog
            {
                UserId = user?.Id,
                UserName = userName,
                IsSuccess = isSuccess,
                EventType = eventType,
                FailureReason = failureReason,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
                RememberDeviceUsed = rememberDeviceUsed,
                AttemptTimeUtc = DateTime.UtcNow
            };

            _context.LoginLogs.Add(log);
            await _context.SaveChangesAsync();
        }

        private class TurnstileResponse
        {
            public bool success { get; set; }
        }
    }
}