using Computer_Security_2FA.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OtpNet;
using QRCoder;

namespace Computer_Security_2FA.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _context;

        public AuthController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        public IActionResult Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = _context.Users.FirstOrDefault(u =>
                u.UserName == model.UserName &&
                u.Password == model.Password);

            if (user == null)
            {
                ViewBag.Message = "Kullanıcı adı veya şifre yanlış!";
                return View(model);
            }

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                ViewBag.Message = "Bu kullanıcı için 2FA kurulumu yapılmamış.";
                return View(model);
            }

            var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
            bool isValid = totp.VerifyTotp(model.Code, out long timeStepMatched, new VerificationWindow(2, 2));

            if (!isValid)
            {
                ViewBag.Message = "Doğrulama kodu yanlış!";
                return View(model);
            }

            HttpContext.Session.SetString("UserName", user.UserName);
            return RedirectToAction("Welcome");
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View(new RegisterViewModel());
        }

        [HttpPost]
        public IActionResult Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            bool userExists = _context.Users.Any(u => u.UserName == model.UserName);
            if (userExists)
            {
                ViewBag.Message = "Bu kullanıcı adı zaten kayıtlı.";
                return View(model);
            }

            var secretKey = KeyGeneration.GenerateRandomKey(20);
            var base32Secret = Base32Encoding.ToString(secretKey);

            var user = new User
            {
                UserName = model.UserName,
                Password = model.Password,
                TwoFactorSecret = base32Secret
            };

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
                return Content("Kullanıcı bulunamadı.");

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
                return Content("2FA secret bulunamadı.");

            var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
            bool isValid = totp.VerifyTotp(code, out long timeStepMatched, new VerificationWindow(2, 2));

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
                ViewBag.Message = "Kod yanlış. Lütfen tekrar deneyin.";

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

            ViewBag.UserName = userName;
            return View();
        }

        [HttpGet]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }
    }
}