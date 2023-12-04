namespace Web2FA.Services.ViewRender
{
    public interface IViewRender
    {
        Task<string> RenderToStringAsync(string viewName, object model);
    }
}
