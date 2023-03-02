using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;

namespace Cryptography
{
    public class Credential
    {
        public string Password { get; set; }
        public string Salt { get; set; }
        public string HashedCredentials { get; set; }
    }

    public class HashHelper
    {
        public string Hash(string secret, byte[] salt)
        {
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(secret, salt, KeyDerivationPrf.HMACSHA512, 100000, 512 / 8));
        }
    }

    class Program
    {
        public static Credential GenerateSaltAndHashedCredentials(string password)
        {
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            string hashedCredentials = new HashHelper().Hash(password, salt);

            return new Credential()
            {
                Password = password,
                Salt = Convert.ToBase64String(salt),
                HashedCredentials = hashedCredentials
            };
        }

        private static bool ValidatePassword(string password, string generatedSalt, string generatedHashCredentials)
        {
            byte[] salt = Convert.FromBase64String(generatedSalt);
            string hashedCredentials = new HashHelper().Hash(password, salt);
            if (generatedHashCredentials != hashedCredentials)
            {
                return false;
            }

            return true;
        }

        static void Main(string[] args)
        {
            string password = "Password123!!!g";
            var generatedCredential = GenerateSaltAndHashedCredentials(password);
            Console.WriteLine($"1. Generate Salt and credential using {password} as password");
            Console.WriteLine($"Password: {generatedCredential.Password}");
            Console.WriteLine($"Salt: {generatedCredential.Salt}");
            Console.WriteLine($"Credentials: {generatedCredential.HashedCredentials}");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("");

            Console.WriteLine($"2. Check credential by using valid password");
            Console.WriteLine($"Password: {password}");
            Console.WriteLine($"Salt: {generatedCredential.Salt}");
            Console.WriteLine($"Credentials: {generatedCredential.HashedCredentials}");
            Console.WriteLine(ValidatePassword(password, generatedCredential.Salt, generatedCredential.HashedCredentials) ? "Credential matches!" : "Credential NOT matches!");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("");

            string newPassword = "newPassword!!!h";
            Console.WriteLine($"3. Check credential by using invalid password");
            Console.WriteLine($"Password: {newPassword}");
            Console.WriteLine($"Salt: {generatedCredential.Salt}");
            Console.WriteLine($"Credentials: {generatedCredential.HashedCredentials}");
            Console.WriteLine(ValidatePassword(newPassword, generatedCredential.Salt, generatedCredential.HashedCredentials) ? "Credential matches!" : "Credential NOT matches!");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("");

            string salt = "QcIIyxM3qdi7f9m01TI84Q==";
            string credential = "qKsfApfQ6pWGXAFqYUUuw3B1xwTJ3SJTs3womQGCDjHYzAOTsXTEbNQpzJwk6Kf/38br1ZZHYSWxuVqqiQ8sCw==";
            Console.WriteLine($"4. Check credential by using hardcoded Salt and Credential.");
            Console.WriteLine($"Password: {password}");
            Console.WriteLine($"Salt: {salt}");
            Console.WriteLine($"Credentials: {credential}");
            Console.WriteLine(ValidatePassword(password, salt, credential) ? "Credential matches!" : "Credential NOT matches!");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }
    }
}
