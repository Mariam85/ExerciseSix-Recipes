using System;
using System.Collections.Generic;
using System.Text;

public class User
{
    public Guid Id { get; set; }
    public string UserName { get; set; }
    public byte[]? PasswordHash { get; set; }
    public byte[]? PasswordSalt { get; set; }

    public User(string userName, byte[] salt, byte[] hash)
    {
        Id = Guid.NewGuid();
        UserName = userName;
        PasswordHash = hash;
        PasswordSalt = salt;
    }
}