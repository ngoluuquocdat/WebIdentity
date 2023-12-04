namespace Web2FA.Services.Email
{
    public class AccountConfirmationModel
    {
        public string BaseUrl { get; set; }
        public string ConfirmationLink { get; set; }
    }

    public class VerificationCodeModel
    {
        public string VerificationCode { get; set; }
    }

    public class ResetPasswordModel
    {
        public string Name { get; set; }
        public string ResetPasswordLink { get; set; }
        public int TokenLifespan { get; set; }  // in hours
    }
}
