using Microsoft.AspNetCore.Mvc;

namespace DEMO.Controllers
{
    public class MyPagesController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
