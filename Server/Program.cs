using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder();
builder.Services.AddControllers();
builder.Services.AddSwaggerGen();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "localhostOnly",
                      policy =>
                      {
                          policy.WithOrigins(builder.Configuration["Client"])
                                .AllowAnyHeader()
                                .AllowAnyMethod()
                                .AllowCredentials();
                      });
});
builder.Services.AddAuthentication(options =>
{
  options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
  o.TokenValidationParameters = new TokenValidationParameters
  {
    ValidateIssuer = true,
    ValidateAudience = true,
    ValidateLifetime = false,
    ValidateIssuerSigningKey = true,
    ValidIssuer = builder.Configuration["Jwt:Issuer"],
    ValidAudience = builder.Configuration["Jwt:Audience"],
    IssuerSigningKey = new SymmetricSecurityKey
    (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});
builder.Services.AddAuthorization();

WebApplication app = builder.Build();
app.Urls.Add(builder.Configuration["Server"]);
app.UseAuthorization();
app.UseAuthentication();
app.UseCors("localhostOnly");

// Creating a token for the user.
app.MapPost("/createToken",
[AllowAnonymous] (User user) =>
{
  var key = Encoding.ASCII.GetBytes
  var audience = builder.Configuration["Jwt:Audience"];
  var issuer = builder.Configuration["Jwt:Issuer"];
  (builder.Configuration["Jwt:Key"]);
  var tokenDescriptor = new SecurityTokenDescriptor
  {
  Subject = new ClaimsIdentity(new[]
  {
	  new Claim("Id", Guid.NewGuid().ToString()),
	  new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
	  new Claim(JwtRegisteredClaimNames.Email, user.UserName),
	  new Claim(JwtRegisteredClaimNames.Jti,
	  Guid.NewGuid().ToString())
	  }),
  Expires = DateTime.UtcNow.AddMinutes(3),
  Issuer = issuer,
  Audience = audience,
  SigningCredentials = new SigningCredentials
  (new SymmetricSecurityKey(key),
  SecurityAlgorithms.HmacSha512Signature)
  };
  var tokenHandler = new JwtSecurityTokenHandler();
  var token = tokenHandler.CreateToken(tokenDescriptor);
  var jwtToken = tokenHandler.WriteToken(token);
  var stringToken = tokenHandler.WriteToken(token);
  return Results.Ok(stringToken);
});

// Generating a token.
app.MapGet("/antiforgery", (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!, new CookieOptions { HttpOnly = false });
});

// Adding a recipe.
app.MapPost("recipes/add-recipe", async (Recipe recipe, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        List<Recipe> recipes = await ReadFile();
        if (recipes.Any())
        {
            recipes.Add(recipe);
            UpdateFile(recipes);
            return Results.Created("Successfully added a recipe", recipe);
        }
        return Results.BadRequest();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Editing a recipe.
app.MapPut("recipes/edit-recipe/{id}", async (Guid id, Recipe editedRecipe, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        List<Recipe> recipes = await ReadFile();
        int index = recipes.FindIndex(r => r.Id == id);
        if (index != -1)
        {
            recipes[index] = editedRecipe;
            recipes[index].Categories.Sort((x, y) => string.Compare(x, y)); ;
            UpdateFile(recipes);
            return Results.Ok(recipes.Find(r => r.Id == id));
        }
        return Results.BadRequest();
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Listing a recipe.
app.MapGet("recipes/list-recipe/{id}", async (Guid id, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        List<Recipe> recipes = await ReadFile();
        Recipe foundRecipe = recipes.Find(r => r.Id == id);
        if (foundRecipe == null)
            return Results.NotFound();
        else
            return Results.Ok(foundRecipe);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Deleting a recipe.
app.MapDelete("recipes/delete-recipe/{id}", async (Guid id, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        List<Recipe> recipes = await ReadFile();
        bool isRemoved = recipes.Remove(recipes.Find(r => r.Id == id));
        if (!isRemoved)
        {
            return Results.BadRequest("This recipe does not exist.");
        }
        else
        {
            UpdateFile(recipes);
            return Results.Ok("Successfuly deleted");
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Adding a category.
app.MapPost("recipes/add-category", async (Categories category, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        List<Categories> categories = await ReadCategories();
        if (categories.Any())
        {
            if (categories.FindIndex(c => c.Name == category.Name) == -1)
            {
                categories.Add(category);
                categories.Sort((x, y) => string.Compare(x.Name, y.Name));
                UpdateCategories(categories);
                return Results.Created("Successfully added a category", category);
            }
            else
            {
                return Results.BadRequest("This category already exists");
            }
        }
        else
        {
            return Results.BadRequest();
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Renaming a category.
app.MapPut("categories/rename-category", async (string oldName, string newName, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        if (oldName == newName)
        {
            return Results.BadRequest("you have entered the same name");
        }

        // Renaming category in the categories file.
        List<Categories> categories = await ReadCategories();
        int index = categories.FindIndex(c => c.Name == oldName);
        if (index != -1)
        {
            if (categories.FindIndex(c => c.Name == newName) == -1)
            {
                categories[index].Name = newName;
                categories.Sort((x, y) => string.Compare(x.Name, y.Name));
                UpdateCategories(categories);

                // Renaming category in the recipes file.
                List<Recipe> recipes = await ReadFile();
                List<Recipe> beforeRename = recipes.FindAll(r => r.Categories.Contains(oldName));
                if (beforeRename.Count != 0)
                {
                    foreach (Recipe r in beforeRename)
                    {
                        int i = r.Categories.FindIndex(cat => cat == oldName);
                        if (i != -1)
                        {
                            r.Categories[i] = newName;
                            r.Categories.Sort((x, y) => string.Compare(x, y));
                        }
                    }
                    UpdateFile(recipes);
                }
                return Results.Ok("Successfully updated");
            }
            else
            {
                return Results.BadRequest("new category name already exists");
            }
        }
        else
        {
            return Results.BadRequest("old category does not exist.");
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Removing a category.
app.MapDelete("recipes/remove-category/{category}", async (string category, HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        // Removing from the categories file.
        List<Categories> categories = await ReadCategories();
        bool isRemoved = categories.Remove(categories.Find(c => c.Name == category));
        if (!isRemoved)
        {
            return Results.BadRequest("This category does not exist.");
        }
        else
        {
            UpdateCategories(categories);
            // Removing from the recipes file.
            List<Recipe> recipes = await ReadFile();
            bool foundRecipe = false;
            foreach (Recipe r in recipes.ToList())
            {
                if (r.Categories[0] == category && r.Categories.Count == 1)
                {
                    foundRecipe = true;
                    recipes.Remove(r);
                }
                else
                {
                    if (r.Categories.Contains(category))
                    {
                        foundRecipe = true;
                        r.Categories.Remove(category);
                    }
                }
            }
            if (foundRecipe)
            {
                UpdateFile(recipes);
            }
            return Results.Ok("Successfuly deleted.");
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Getting the json file content to display it.
app.MapGet("recipes", async (HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        List<Recipe> recipes = await ReadFile();
        return Results.Ok(recipes);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Getting the json file content of the categories.
app.MapGet("categories", async (HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
        List<Categories> recipes = await ReadCategories();
        return Results.Ok(recipes);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});
app.Run();

// Reading the recipes json file content.
static async Task<List<Recipe>> ReadFile()
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Text.json");
    string sFilePath = Path.GetFullPath(sFile);
    string jsonString = await File.ReadAllTextAsync(sFilePath);
    List<Recipe>? menu = System.Text.Json.JsonSerializer.Deserialize<List<Recipe>>(jsonString);
    return menu;
}

// Reading the categories json file content.
static async Task<List<Categories>> ReadCategories()
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Categories.json");
    string sFilePath = Path.GetFullPath(sFile);
    string jsonString = await File.ReadAllTextAsync(sFilePath);
    List<Categories>? menu = System.Text.Json.JsonSerializer.Deserialize<List<Categories>>(jsonString);
    return menu;
}

// Updating the recipes json file content.
static async void UpdateFile(List<Recipe> newRecipes)
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Text.json");
    string sFilePath = Path.GetFullPath(sFile);
    var options = new JsonSerializerOptions { WriteIndented = true };
    File.WriteAllText(sFilePath, System.Text.Json.JsonSerializer.Serialize(newRecipes));
}

// Updating the categories json file content.
static async void UpdateCategories(List<Categories> newRecipes)
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Categories.json");
    string sFilePath = Path.GetFullPath(sFile);
    var options = new JsonSerializerOptions { WriteIndented = true };
    File.WriteAllText(sFilePath, System.Text.Json.JsonSerializer.Serialize(newRecipes));
}