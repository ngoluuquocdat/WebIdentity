using Microsoft.AspNetCore.Mvc.Rendering;

namespace Web2FA.Models.AccountViewModels
{
    public class SendCodeViewModel
    {
        public TwoFactorProvider SelectedProvider { get; set; } = TwoFactorProvider.Email;

        public ICollection<SelectListItem> Providers { get; set; }

        public string ReturnUrl { get; set; }

        public bool RememberMe { get; set; }
    }
}
