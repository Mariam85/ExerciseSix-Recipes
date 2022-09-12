using System;

public class User
{
    public Guid Id { get; set; }
    public string UserName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    public User(string userName, string password)
    {
        Id = Guid.NewGuid();
        UserName = userName;
        Password = password;
    }
}