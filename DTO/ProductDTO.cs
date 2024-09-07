namespace ProductsAPI.DTO
{
    public class ProductDTO
    {
        public int ProductID { get; set; }

        public string ProductName { get; set; } = null!;
        public decimal Price { get; set; }
    }
}