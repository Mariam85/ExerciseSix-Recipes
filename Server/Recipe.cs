using System;
using System.Collections.Generic;
using System.Text;

public class Recipe
{
    public Guid Id { get; set; }
    public List<string> Ingredients { get; set; } = new List<string>();
    public string Title { get; set; }
    public List<string> Instructions { get; set; } = new List<string>();
    public List<string> Categories { get; set; } = new List<string>();

    public Recipe(List<string> ingredients, string title, List<string> instructions, List<string> categories)
    {
        Id = Guid.NewGuid();
        this.Ingredients = ingredients;
        this.Title = title;
        this.Instructions = instructions;
        this.Categories = categories;
    }
}