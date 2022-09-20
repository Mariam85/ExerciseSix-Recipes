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
using Newtonsoft.Json;
using Microsoft.AspNetCore.SignalR;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder();
var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorisation",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JWT authentication for MinimalAPI"
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
    Email = "mariammostafa.493@gmail.com",
    Url = new Uri("https://github.com/Mariam85")
};

var license = new OpenApiLicense()
{
    Name = "Free License"
};

var info = new OpenApiInfo()
{
    Version = "V1",
    Title = "Recipes Api with JWT Authentication",
    Description = "Recipes Api with JWT Authentication",
    Contact = contactInfo,
    License = license
};

IConfiguration config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json")
    .AddEnvironmentVariables()
    .Build();

var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: MyAllowSpecificOrigins,
                      policy =>
                      {
                          policy.WithOrigins(config["Client"])
            .AllowAnyHeader()
            .AllowAnyMethod()
            .WithExposedHeaders("IS-TOKEN-EXPIRED")
            .AllowCredentials();
                      });
});
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    var Key = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
    o.SaveToken = true;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["JWT:Issuer"],
        ValidAudience = builder.Configuration["JWT:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Key),
        ClockSkew = TimeSpan.FromSeconds(0)
    };
    o.Events = new JwtBearerEvents
    {

        OnAuthenticationFailed = context =>
        {
            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                context.Response.Headers.Add("IS-TOKEN-EXPIRED", "true");
            }
            return Task.CompletedTask;
        }
    };
});
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", info);
    options.AddSecurityDefinition("Bearer", securityScheme);
    options.AddSecurityRequirement(securityRequirements);
});

WebApplication app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI();
app.UseHttpsRedirection();
app.UseCors(MyAllowSpecificOrigins);
app.UseAuthentication();
app.UseAuthorization();

// Reading Users.json
string usersFile = "Users.json";
string jsonUsersString;
var usersList = new List<User>();
if (File.Exists(usersFile))
{
    if (new FileInfo(usersFile).Length > 0)
    {
        jsonUsersString = await File.ReadAllTextAsync(usersFile);
        usersList = JsonConvert.DeserializeObject<List<User>>(jsonUsersString)!;
    }
}
else
{
    File.Create(usersFile).Dispose();
}

// Logining in endpoint.
app.MapPost("/account/login", [AllowAnonymous] async (string userName, string password) =>
{
    // Checking if the user exists.
    var index = usersList.FindIndex((u) => u.UserName == userName);
    if (index == -1)
    {
        return Results.BadRequest("This user does not exist.");
    }
    // Verifying the password.
    using (var hmac = new HMACSHA512(usersList[index].PasswordSalt))
    {
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        if (!computedHash.SequenceEqual(usersList[index].PasswordHash))
        {
            return Results.BadRequest("The password entered is incorrect.");
        }
    }
    // Creating the token.
    var secureKey = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
    var securityKey = new SymmetricSecurityKey(secureKey);
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512);
    var jwtTokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new System.Security.Claims.ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Name,usersList[index].UserName),
        }),
        Expires = DateTime.Now.AddMinutes(20),
        SigningCredentials = credentials
    };
    var token = jwtTokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = jwtTokenHandler.WriteToken(token);
    if (jwtToken != null)
    {
        var refresh = RandomString(35);
        usersList[index].RefreshToken = refresh;
        await SaveAsync();
        return Results.Ok(new { Token = jwtToken, Refresh = refresh });
    }
    else
    {
        return Results.Unauthorized();
    }
});

// Generating a random string for the refresh token.
string RandomString(int length)
{
    var random = new Random();
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return new string(Enumerable.Repeat(chars, length).Select(x => x[random.Next(x.Length)]).ToArray());
}

// Validating the password.
bool ValidatePassword(string password)
{
    int validConditions = 0;
    foreach (char c in password)
    {
        if (c >= 'a' && c <= 'z')
        {
            validConditions++;
            break;
        }
    }
    foreach (char c in password)
    {
        if (c >= 'A' && c <= 'Z')
        {
            validConditions++;
            break;
        }
    }
    if (validConditions == 0) return false;
    foreach (char c in password)
    {
        if (c >= '0' && c <= '9')
        {
            validConditions++;
            break;
        }
    }
    if (validConditions == 1) return false;
    if (validConditions == 2)
    {
        char[] special = { '@', '#', '$', '%', '^', '&', '+', '=' };
        if (password.IndexOfAny(special) == -1) return false;
    }
    return true;
}

// Validating the username.
bool ValidateUsername(string username)
{
    if (username.Length > 30 || username.Length < 8)
    {
        return false;
    }
    int validConditions = 0;
    // Checking that at least 1 letter exists. 
    foreach (char c in username)
    {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
        {
            validConditions++;
            break;
        }
    }
    if (validConditions == 0)
    {
        return false;
    }
    // Checking that at least 1 number exists. 
    foreach (char c in username)
    {
        if (c >= '0' && c <= '9')
        {
            validConditions++;
            break;
        }
    }
    if (validConditions <= 1)
    {
        return false;
    }
    else
    {
        return true;
    }
}

// Signing up endpoint.
app.MapPost("/account/signup", [AllowAnonymous] async (string userName, string password) =>
{
    if (usersList.Find((x) => x.UserName == userName) != null)
    {
        return Results.BadRequest("Username already exists");
    }
    else if (userName.IsNullOrEmpty() || ValidateUsername(userName) == false)
    {
        return Results.BadRequest("Username is invalid");
    }
    else if (password.IsNullOrEmpty() || ValidatePassword(password) == false)
    {
        return Results.BadRequest("Password is invalid");
    }
    else
    {
        byte[] passwordSalt = { };
        byte[] passwordHash = { };
        using (var hmac = new HMACSHA512())
        {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
        User user = new(userName, passwordSalt, passwordHash, "");
        usersList.Add(user);
        await SaveAsync();
        return Results.Ok(user);
    }
});

// Refreshing the token.
app.MapPost("token/refresh-token", async (string refreshToken) =>
{
    var index = usersList.FindIndex((u) => u.RefreshToken == refreshToken);
    if (index != -1)
    {
        // Creating the token.
        var secureKey = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
        var securityKey = new SymmetricSecurityKey(secureKey);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512);
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new[]
            {
            new Claim(JwtRegisteredClaimNames.Name,usersList[index].UserName)
        }),
            Expires = DateTime.Now.AddMinutes(20),
            SigningCredentials = credentials
        };
        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);
        if (jwtToken != null)
        {
            var refresh = RandomString(35);
            usersList[index].RefreshToken = refresh;
            try
            {
                await SaveAsync();
                return Results.Ok(new { Token = jwtToken, Refresh = refresh });
            }
            catch
            {
                return Results.Unauthorized();
            }
        }
        else
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        return Results.Unauthorized();
    }
});

// Adding a recipe.
app.MapPost("recipes/add-recipe", [Authorize] async (Recipe recipe) =>
{
    try
    {
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
app.MapPut("recipes/edit-recipe/{id}", [Authorize] async (Guid id, Recipe editedRecipe) =>
{
    try
    {
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
app.MapGet("recipes/list-recipe/{id}", [Authorize] async (Guid id) =>
{
    try
    {
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
app.MapDelete("recipes/delete-recipe/{id}", [Authorize] async (Guid id) =>
{
    try
    {
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
app.MapPost("recipes/add-category", [Authorize] async (Categories category) =>
{
    try
    {
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
app.MapPut("categories/rename-category", [Authorize] async (string oldName, string newName) =>
{
    try
    {
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
app.MapDelete("recipes/remove-category/{category}", [Authorize] async (string category) =>
{
    try
    {
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
app.MapGet("recipes", [Authorize] async () =>
{
    try
    {
        List<Recipe> recipes = await ReadFile();
        return Results.Ok(recipes);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex?.Message ?? string.Empty);
    }
});

// Getting the json file content of the categories.
app.MapGet("categories", [Authorize] async () =>
{
    try
    {
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
    List<Recipe> menu = System.Text.Json.JsonSerializer.Deserialize<List<Recipe>>(jsonString)!;
    return menu;
}

// Reading the categories json file content.
static async Task<List<Categories>> ReadCategories()
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Categories.json");
    string sFilePath = Path.GetFullPath(sFile);
    string jsonString = await File.ReadAllTextAsync(sFilePath);
    List<Categories> menu = System.Text.Json.JsonSerializer.Deserialize<List<Categories>>(jsonString)!;
    return menu;
}

// Updating the recipes json file content.
static async void UpdateFile(List<Recipe> newRecipes)
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Text.json");
    string sFilePath = Path.GetFullPath(sFile);
    var options = new JsonSerializerOptions { WriteIndented = true };
    await File.WriteAllTextAsync(sFilePath, System.Text.Json.JsonSerializer.Serialize(newRecipes, options));
}

// Updating the categories json file content.
static async void UpdateCategories(List<Categories> newRecipes)
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Categories.json");
    string sFilePath = Path.GetFullPath(sFile);
    var options = new JsonSerializerOptions { WriteIndented = true };
    await File.WriteAllTextAsync(sFilePath, System.Text.Json.JsonSerializer.Serialize(newRecipes, options));
}

// Updating the users json file content.
async Task SaveAsync()
{
    string sCurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
    string sFile = System.IO.Path.Combine(Environment.CurrentDirectory, "Users.json");
    string sFilePath = Path.GetFullPath(sFile);
    await File.WriteAllTextAsync(sFilePath, JsonConvert.SerializeObject(usersList));
}