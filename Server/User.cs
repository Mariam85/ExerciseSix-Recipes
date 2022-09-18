using System;
using System.Collections.Generic;
using System.Text;

public class User
{
    public Guid Id { get; set; }
    public string UserName { get; set; }
    public byte[]? PasswordHash { get; set; }
    public byte[]? PasswordSalt { get; set; }
    public string RefreshToken { get; set; } = String.Empty;

    public User(string userName, byte[] salt, byte[] hash,string refresh)
    {
        Id = Guid.NewGuid();
        UserName = userName;
        PasswordHash = hash;
        PasswordSalt = salt;
        RefreshToken = refresh;
    }
}