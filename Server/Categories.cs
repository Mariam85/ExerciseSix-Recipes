using System;
using System.Collections.Generic;
using System.Text;

public class Categories
{
    public Guid Id { get; set; }
    public string Name { get; set; }

    public Categories(string name)
    {
        Id = Guid.NewGuid();
        this.Name = name;
    }
}