namespace ProductsAPI.Models
{
    public class Product
    {
        public int ProductID { get; set; }

        public string ProductName { get; set; } = null!;
        public decimal Price { get; set; }

        public bool IsActive { get; set; }
    }
}