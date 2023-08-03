using System.Security.Cryptography;
using System.IO;
using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;


public class AES_Encryptor
{
    private static byte[] AESEncryptBytes(byte[] clearBytes, byte[] passBytes, byte[] saltBytes)
    {
        byte[] encryptedBytes = null;

        // create a key from the password and salt, use 32K iterations – see note
        var key = new Rfc2898DeriveBytes(passBytes, saltBytes, 32768);

        // create an AES object
        using (Aes aes = new AesManaged())
        {
            // set the key size to 256
            aes.KeySize = 256;
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(clearBytes, 0, clearBytes.Length);
                    cs.Close();
                }
                encryptedBytes = ms.ToArray();
            }
        }
        return encryptedBytes;
    }

    private static byte[] AESDecryptBytes(byte[] cryptBytes, byte[] passBytes, byte[] saltBytes)
    {
        byte[] clearBytes = null;

        // create a key from the password and salt, use 32K iterations
        var key = new Rfc2898DeriveBytes(passBytes, saltBytes, 32768);

        using (Aes aes = new AesManaged())
        {
            // set the key size to 256
            aes.KeySize = 256;
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cryptBytes, 0, cryptBytes.Length);
                    cs.Close();
                }
                clearBytes = ms.ToArray();
            }
        }
        return clearBytes;
    }

    public static bool ByteArrayToFile(string fileName, byte[] byteArray)
    {
        try
        {
            using (var fs = new FileStream(fileName, FileMode.Create, FileAccess.Write))
            {
                fs.Write(byteArray, 0, byteArray.Length);
                return true;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception caught in process: {0}", ex);
            return false;
        }
    }

    public static string RandomString(int length)
    {
        const string src = "abcdefghijklmnopqrstuvwxyz0123456789";
        var sb = new StringBuilder();
        Random RNG = new Random();
        for (var i = 0; i < length; i++)
        {
            var c = src[RNG.Next(0, src.Length)];
            sb.Append(c);
        }
        return sb.ToString();
    }

    public static void Main(string[] args)
    {



        string passcode = RandomString(16);

        byte[] passBytes = Encoding.ASCII.GetBytes(passcode);

        byte[] fileToEnc = File.ReadAllBytes(args[0]);

        //enc 3 times
        byte[] cryptBytes = AESEncryptBytes(AESEncryptBytes(AESEncryptBytes(AESEncryptBytes(fileToEnc, passBytes, passBytes), passBytes, passBytes), passBytes, passBytes), passBytes, passBytes);

        byte[] test = AESDecryptBytes(AESDecryptBytes(AESDecryptBytes(AESDecryptBytes(cryptBytes, passBytes, passBytes), passBytes, passBytes), passBytes, passBytes), passBytes, passBytes);

        //ENC FILE
        //ByteArrayToFile(args[0] + ".enc", cryptBytes);

        //ENC.JPG FILE
        //byte[] jpng_magic = { 0xFF, 0xD8, 0xFF, 0xDB };
        //ByteArrayToFile(args[0] + ".enc.jpg", jpng_magic.Concat(cryptBytes).ToArray());

        //TXT
        var newname = args[0];
        newname = newname.Replace(".exe", "") + ".txt";
        var base64PE = Convert.ToBase64String(cryptBytes);
        File.WriteAllText(newname, base64PE);

        //OUTPUT
        Console.WriteLine("[*] Success!!");
        Console.WriteLine("[*] The Passcode is : " + passcode);
        //Console.WriteLine(base64PE);



    }
}
