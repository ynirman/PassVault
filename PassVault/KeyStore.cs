using System;
using System.Security.Cryptography;
using System.Text;

public class StoreKey
{
    public static String GenKey_SaveInContainer(string containerName)
    {
        // Create the CspParameters object and set the key container
        // name used to store the RSA key pair.
        var parameters = new CspParameters
        {
            KeyContainerName = containerName
        };

        // Create a new instance of RSACryptoServiceProvider that accesses
        // the key container MyKeyContainerName.
        using var rsa = new RSACryptoServiceProvider(parameters)
        {
            // If a key container with the specified name does exist, then the key in the container is automatically loaded.
            PersistKeyInCsp = true
        };
        // Display the key information to the console.
        return ($"Key added to container: \n  {rsa.ToXmlString(true)}");
    }

    public static String GetKeyFromContainer(string containerName)
    {
        // Create the CspParameters object and set the key container
        // name used to store the RSA key pair.
        var parameters = new CspParameters
        {
            KeyContainerName = containerName
        };

        // Create a new instance of RSACryptoServiceProvider that accesses
        // the key container MyKeyContainerName.
        using var rsa = new RSACryptoServiceProvider(parameters)
        {
            // If a key container with the specified name does exist, then the key in the container is automatically loaded.
            PersistKeyInCsp = true
        };

        // Display the key information to the console.
        return $"Key retrieved from container : \n {rsa.ToXmlString(true)}";
    }

    public static String DeleteKeyFromContainer(string containerName)
    {
        // Create the CspParameters object and set the key container
        // name used to store the RSA key pair. 
        // If a key container with the specified name does exist, then the key in the container is automatically loaded
        var parameters = new CspParameters
        {
            KeyContainerName = containerName
        };

        // Create a new instance of RSACryptoServiceProvider that accesses
        // the key container.
        using var rsa = new RSACryptoServiceProvider(parameters)
        {
            // Delete the key entry in the container.
            PersistKeyInCsp = false
        };

        // Call Clear to release resources and delete the key from the container.
        rsa.Clear();

        return ("Key deleted.");
    }

    // Return the public key portion of the rsa ket pair
    public static String getPublicKeyFromContainer(string containerName)
    {
        // Create the CspParameters object and set the key container
        // name used to store the RSA key pair.
        var parameters = new CspParameters
        {
            KeyContainerName = containerName
        };

        // Create a new instance of RSACryptoServiceProvider that accesses
        // the key container MyKeyContainerName.
        using var rsa = new RSACryptoServiceProvider(parameters)
        {
            // If a key container with the specified name does exist, then the key in the container is automatically loaded.
            PersistKeyInCsp = true
        };

        return ($"Public key retrieved from container : \n {Convert.ToBase64String(rsa.ExportRSAPublicKey())}");
    }
}