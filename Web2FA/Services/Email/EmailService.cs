using System.Net.Mail;
using System.Net.Mime;
using System.Net;
using MimeKit;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using MimeKit.Text;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Web;
using Web2FA.Services.ViewRender;

namespace Web2FA.Services.Email
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IViewRender _viewRenderService;
        public EmailService(IConfiguration config, 
            IHttpContextAccessor httpContextAccessor,
            IViewRender viewRenderService)
        {
            _config = config;
            _httpContextAccessor = httpContextAccessor;
            _viewRenderService = viewRenderService;
        }


        public async void SendAccountConfirmationEmail(string email, string confirmationLink)
        {
            string templatePath = "/Views/Templates/Email/EmailConfirmation.cshtml";
            string subject = "Your Web Identity account confirmation";

            var request = _httpContextAccessor.HttpContext.Request;            
            string baseUrl = $"{request.Scheme}://{request.Host}{request.PathBase}";

            AccountConfirmationModel model = new AccountConfirmationModel
            {
                BaseUrl = baseUrl,
                ConfirmationLink = confirmationLink
            };

            string content = await _viewRenderService.RenderToStringAsync(templatePath, model);
            SendEmail(email, subject, content);
        }

        public async void SendVerificationCode(string email, string verificationCode)
        {
            string templatePath = "/Views/Templates/Email/VerificationCode.cshtml";
            string subject = "Your Web Identity verification code";

            VerificationCodeModel model = new VerificationCodeModel
            {
                VerificationCode = verificationCode,
            };

            string content = await _viewRenderService.RenderToStringAsync(templatePath, model);
            SendEmail(email, subject, content);
        }

        public async void SendResetPasswordConfirmation(string email, string resetPasswordLink, int tokenLifespan)
        {
            string templatePath = "/Views/Templates/Email/ResetPassword.cshtml";
            string subject = "Password recovery request";

            var request = _httpContextAccessor.HttpContext.Request;
            string baseUrl = $"{request.Scheme}://{request.Host}{request.PathBase}";

            ResetPasswordModel model = new ResetPasswordModel
            {
                ResetPasswordLink = resetPasswordLink,
                TokenLifespan = tokenLifespan
            };

            string content = await _viewRenderService.RenderToStringAsync(templatePath, model);
            SendEmail(email, subject, content);
        }

        public void SendEmail(string email, string subject, string content)
        {
            string MyEmailAddress = "app.happyvacation@gmail.com";
            string Password = "acczlkdoaiygvgse";

            MailAddress from = new MailAddress(MyEmailAddress, "Web2FA System");
            MailAddress to = new MailAddress(email);
            var message = new MailMessage(from, to);
            message.Subject = subject;

            message.Body = content;
            message.IsBodyHtml = true;

            var bodyBuilder = new BodyBuilder();
            bodyBuilder.HtmlBody = content;

            // send email
            using (SmtpClient smtp = new SmtpClient("smtp.gmail.com", 587))
            {
                smtp.EnableSsl = true;
                smtp.UseDefaultCredentials = false;
                smtp.Credentials = new NetworkCredential(MyEmailAddress, Password);
                smtp.Send(message);
            }
        }
    }
}
