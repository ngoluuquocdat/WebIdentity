namespace Web2FA.Services.Email
{
    public interface IEmailService
    {
        void SendEmail(string email, string subject, string content);
        void SendAccountConfirmationEmail(string email, string confirmationLink);
        void SendVerificationCode(string email, string verificationCode);
        void SendResetPasswordConfirmation(string email, string resetPasswordLink, int tokenLifespan);
    }
}
