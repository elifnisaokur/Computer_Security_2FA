using Computer_Security_2FA.Models;
using Microsoft.AspNetCore.Mvc;
using OtpNet;
using QRCoder;
using System.Diagnostics;

namespace Computer_Security_2FA.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _context;

        public HomeController(ILogger<HomeController> logger, ApplicationDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Enable2FA()
        {
            var user = _context.Users.FirstOrDefault(u => u.UserName == "testuser");
            if (user == null)
                return Content("Kullanıcı bulunamadı!");

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                var secretKey = KeyGeneration.GenerateRandomKey(20);
                user.TwoFactorSecret = Base32Encoding.ToString(secretKey);
                _context.SaveChanges();
            }

            var base32Secret = user.TwoFactorSecret!;

            string issuer = "MyApp";
            string otpauth = $"otpauth://totp/{issuer}:{user.UserName}?secret={base32Secret}&issuer={issuer}";

            using var qrGenerator = new QRCodeGenerator();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(otpauth, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new PngByteQRCode(qrCodeData);
            string base64Qr = Convert.ToBase64String(qrCode.GetGraphic(20));

            ViewBag.QR = base64Qr;
            ViewBag.Secret = base32Secret;

            return View();
        }

        [HttpGet]
        public IActionResult Verify2FA()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Verify2FA(string code)
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                ViewBag.Message = "Kod girilmedi!";
                return View();
            }

            var user = _context.Users.FirstOrDefault(u => u.UserName == "testuser");
            if (user == null)
            {
                ViewBag.Message = "Kullanıcı bulunamadı!";
                return View();
            }

            if (string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                ViewBag.Message = "2FA aktif değil!";
                return View();
            }

            var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
            bool isValid = totp.VerifyTotp(code, out long timeStepMatched, new VerificationWindow(2, 2));

            ViewBag.Message = isValid ? "Kod doğru!" : "Kod yanlış!";
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}