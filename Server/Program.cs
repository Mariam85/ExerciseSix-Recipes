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
using System.Security.Cryptography;
using System.ComponentModel;

var builder = WebApplication.CreateBuilder();
var securityScheme = new OpenApiSecurityScheme()
{ 
    Name = "Authorisation",
    Type = SecuritySchemeType.ApiKey,
    Scheme="Bearer",
    BearerFormat = "JWT",
    In =ParameterLocation.Header,
    Description="JWT authentication for MinimalAPI"
};

var securityRequirements = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type= ReferenceType.SecurityScheme,
                Id="Bearer"
            }
        },
        new string[] {}
    }
};

var contactInfo = new OpenApiContact()
{
    Name = "Mariam Mostafa",
    Email="mariammostafa.493@gmail.com",
    Url = new Uri("https://github.com/Mariam85")
};

var license = new OpenApiLicense()
{ 
   Name = "Free License"
};

var info = new OpenApiInfo()
{
    Version="V1",
    Title="Recipes Api with JWT Authentication",
    Description="Recipes Api with JWT Authentication",
    Contact= contactInfo,
    License= license
};

builder.Services.AddControllers();
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
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1",info);
    options.AddSecurityDefinition("Bearer",securityScheme);
    options.AddSecurityRequirement(securityRequirements);
});

WebApplication app = builder.Build();
app.Urls.Add(builder.Configuration["Server"]);
app.UseAuthentication();
app.UseAuthorization();
app.UseCors("localhostOnly");
app.UseSwagger();
app.UseSwaggerUI();


// Logining in endpoint.
app.MapPost("/account/login", [AllowAnonymous] async (string userName,string password) =>
{
    // Checking if the user exists.
    var usersList=await ReadUsers();
    User? foundUser=usersList.Find((u) => u.UserName == userName);
    if(foundUser == null)
    {
        return Results.BadRequest("This user does not exist.");
    }

    // Verifying the password.
    using (var hmac = new HMACSHA512(foundUser.PasswordSalt))
    {
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        if(!computedHash.SequenceEqual(foundUser.PasswordHash))
        {
            return Results.BadRequest("The password entered is incorrect.");
        }
    }

    // Creating the token.
    var secureKey = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
    var issuer = builder.Configuration["Jwt:Issuer"];
    var audience = builder.Configuration["Jwt:Audience"];
    var securityKey= new SymmetricSecurityKey(secureKey);
    var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha512);
   
    var jwtTokenHandler=new JwtSecurityTokenHandler();
    var tokenDescriptor=new SecurityTokenDescriptor
    {
        Subject = new System.Security.Claims.ClaimsIdentity(new[]
        {
            new Claim("Id",foundUser.Id.ToString()),  
            new Claim(JwtRegisteredClaimNames.Sub,foundUser.UserName),
            new Claim(JwtRegisteredClaimNames.Email,foundUser.UserName),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
        }),
        Expires = DateTime.Now.AddHours(2),
        Audience=audience,
        Issuer=issuer,
        SigningCredentials=credentials
        };
    var token=jwtTokenHandler.CreateToken(tokenDescriptor);
    var jwtToken=jwtTokenHandler.WriteToken(token);
    return Results.Ok(jwtToken);
    
});

// Signing up endpoint.
app.MapPost("/account/signup", [AllowAnonymous] async (string userName,string password) =>
{
    var usersList=await ReadUsers();
    if (password.IsNullOrEmpty() || password.Length<8)
    {
       return Results.BadRequest("Password is invalid");
    }
    else if(usersList.Find((x) => x.UserName == userName)!=null)
    {
        return Results.BadRequest("Username already exists");
    }
    else if(userName.IsNullOrEmpty())
    {
        return Results.BadRequest("Username is invalid");
    }
    else
    { 
        byte[] passwordSalt={};
        byte[] passwordHash={};
        using (var hmac= new HMACSHA512())
        {
          passwordSalt = hmac.Key;
          passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
        User user=new(userName,passwordSalt,passwordHash);
        usersList.Add(user);
        UpdateUsers(usersList);
        return Results.Ok(user);
    }
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

// Reading the users json file content.
static async Task<List<User>> ReadUsers()
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Users.json");
    string sFilePath = Path.GetFullPath(sFile);
    string jsonString = await File.ReadAllTextAsync(sFilePath);
    List<User>? users = System.Text.Json.JsonSerializer.Deserialize<List<User>>(jsonString);
    return users;
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

// Updating the users json file content.
static async void UpdateUsers(List<User> usersList)
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Users.json");
    string sFilePath = Path.GetFullPath(sFile);
    var options = new JsonSerializerOptions { WriteIndented = true };
    File.WriteAllText(sFilePath, System.Text.Json.JsonSerializer.Serialize(usersList));
}