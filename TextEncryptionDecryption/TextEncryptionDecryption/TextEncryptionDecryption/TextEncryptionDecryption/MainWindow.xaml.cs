using System;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Security.Cryptography;
using System.IO;

namespace TextEncryptionDecryption
{
    public partial class MainWindow : Window
    {
        private byte[] Key1, Key2, Key3;
        public MainWindow()
        {
            InitializeComponent();
            selectionBox1.Items.Add("BASE64");
            selectionBox1.Items.Add("Hexadecimal");

            selectionBox2.Items.Add("BASE64");
            selectionBox2.Items.Add("Hexadecimal");

            selectionBox3.Items.Add("BASE64");
            selectionBox3.Items.Add("Hexadecimal");
        }

        // Method to convert a hexadecimal string to a byte array
        private byte[] ConvertHexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        // AES
        private byte[] EncryptAes(string plainText, byte[] key)
        {
            // Create an AES algorithm
            using (Aes aesAlg = Aes.Create())
            {
                // Set key, IV, padding mode, and cipher mode for the AES algorithm
                aesAlg.Key = key;
                aesAlg.IV = new byte[16]; // 128 bits (16 bytes)
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Mode = CipherMode.ECB;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = aesAlg.CreateEncryptor();

                // Convert plainText to bytes
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] encryptedBytes;

                // Create a memory stream to store the encrypted data
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Create a CryptoStream to write the encrypted data to the memory stream
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }
                return encryptedBytes;
            }
        }

        private void Button1_Click(object sender, RoutedEventArgs e)
        {
            string plainText = textBox1.Text;
            byte[] Key = Encoding.UTF8.GetBytes(textBox2.Text);
            byte[] encryptedData = EncryptAes(plainText, Key);

            string Encode = selectionBox1.SelectedItem.ToString();

            switch (Encode)
            {
                // Convert the encrypted bytes to a Base64 string
                case "BASE64":
                    textBox3.Text = Convert.ToBase64String(encryptedData);
                    break;
                // Convert the encrypted bytes to a hexadecimal string without dashes
                case "Hexadecimal":
                    textBox3.Text = BitConverter.ToString(encryptedData).Replace("-", "");
                    break;
                // Throw an exception if the encoding format is invalid
                default:
                    throw new ArgumentException("Invalid encoding format");
            }
        }

        private void SecretKey_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 16)
            {
                // If the text length exceeds 16 characters, trim it to 16 characters
                textBox.Text = textBox.Text.Substring(0, 16);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private byte[] DecryptAes(byte[] cipherText, byte[] key)
        {
            // Create an AES algorithm
            using (Aes aesAlg = Aes.Create())
            {
                // Set key, IV, padding mode, and cipher mode for the AES algorithm
                aesAlg.Key = key;
                aesAlg.IV = new byte[16];
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Mode = CipherMode.ECB;

                // Create an decryptor using the key and IV
                ICryptoTransform decryptor = aesAlg.CreateDecryptor();

                byte[] decryptedBytes;

                // Create a memory stream from the input ciphertext byte array
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    // Create a CryptoStream to read the decrypted data from the memory stream
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Create a memory stream to store the decrypted result
                        using (MemoryStream msResult = new MemoryStream())
                        {
                            csDecrypt.CopyTo(msResult);
                            decryptedBytes = msResult.ToArray();
                        }
                    }
                }
                return decryptedBytes;
            }
        }

        private string AES(string cipherText, byte[] Key)
        {
            string Encode = selectionBox1.SelectedItem.ToString();
            byte[] encryptedData;

            if (Encode == "BASE64")
            {
                // Convert Base64 input to byte array
                encryptedData = Convert.FromBase64String(cipherText);
            }
            else if (Encode == "Hexadecimal")
            {
                // Convert hexadecimal input to byte array
                encryptedData = ConvertHexStringToByteArray(cipherText);
            }
            else
            {
                // Handle invalid encoding selection
                throw new ArgumentException("Invalid encoding selected");
            }

            // Decrypt the data
            byte[] decryptedData = DecryptAes(encryptedData, Key);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            return decryptedText;
        }

        private void Button2_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = textBox3.Text;
            byte[] Key = Encoding.UTF8.GetBytes(textBox2.Text);
            string decryptedText = AES(cipherText, Key);

            // Display the decrypted text
            textBox4.Text = decryptedText;
        }

        // DES
        private byte[] EncryptDes(string plainText, byte[] key)
        {
            // Create an DES algorithm
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                // Set key, IV, padding mode, and cipher mode for the DES algorithm
                desAlg.Key = key;
                desAlg.IV = new byte[8]; // 64 bits (8 bytes)
                desAlg.Padding = PaddingMode.Zeros;
                desAlg.Mode = CipherMode.ECB;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = desAlg.CreateEncryptor();

                // Convert plainText to bytes
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] encryptedBytes;

                // Create a memory stream to store the encrypted data
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Create a CryptoStream to write the encrypted data to the memory stream
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        csEncrypt.FlushFinalBlock();
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }
                return encryptedBytes;
            }
        }

        private void SecretKeyDES_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 8)
            {
                // If the text length exceeds 8 characters, trim it to 8 characters
                textBox.Text = textBox.Text.Substring(0, 8);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private void Button3_Click(object sender, RoutedEventArgs e)
        {
            string plainText = textBox5.Text;
            byte[] Key = Encoding.UTF8.GetBytes(textBox6.Text);
            byte[] encryptedData = EncryptDes(plainText, Key);

            string Encode = selectionBox2.SelectedItem.ToString();

            switch (Encode)
            {
                // Convert the encrypted bytes to a Base64 string
                case "BASE64":
                    textBox7.Text = Convert.ToBase64String(encryptedData);
                    break;
                // Convert the encrypted bytes to a hexadecimal string without dashes
                case "Hexadecimal":
                    textBox7.Text = BitConverter.ToString(encryptedData).Replace("-", "");
                    break;
                // Throw an exception if the encoding format is invalid
                default:
                    throw new ArgumentException("Invalid encoding format");
            }
        }

        private byte[] DecryptDes(byte[] cipherText, byte[] key)
        {
            // Create an DES algorithm
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                // Set key, IV, padding mode, and cipher mode for the DES algorithm
                desAlg.Key = key;
                desAlg.IV = new byte[8];
                desAlg.Padding = PaddingMode.Zeros;
                desAlg.Mode = CipherMode.ECB;

                // Create an decryptor using the key and IV
                ICryptoTransform decryptor = desAlg.CreateDecryptor();

                byte[] decryptedBytes;

                // Create a memory stream from the input ciphertext byte array
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    // Create a CryptoStream to read the decrypted data from the memory stream
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Create a memory stream to store the decrypted result
                        using (MemoryStream msResult = new MemoryStream())
                        {
                            csDecrypt.CopyTo(msResult);
                            decryptedBytes = msResult.ToArray();
                        }
                    }
                }
                return decryptedBytes;
            }
        }

        private string DES(string cipherText, byte[] Key)
        {
            string Encode = selectionBox2.SelectedItem.ToString();
            byte[] encryptedData;

            if (Encode == "BASE64")
            {
                // Convert Base64 input to byte array
                encryptedData = Convert.FromBase64String(cipherText);
            }
            else if (Encode == "Hexadecimal")
            {
                // Convert hexadecimal input to byte array
                encryptedData = ConvertHexStringToByteArray(cipherText);
            }
            else
            {
                // Handle invalid encoding selection
                throw new ArgumentException("Invalid encoding selected");
            }
            byte[] decryptedData = DecryptDes(encryptedData, Key);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            return decryptedText;
        }

        private void Button4_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = textBox7.Text;
            byte[] Key = Encoding.UTF8.GetBytes(textBox6.Text);
            string decryptedText = DES(cipherText, Key);

            // Display the decrypted text
            textBox8.Text = decryptedText;
        }

        // TDES
        private byte[] EncryptTDes(string plainText, byte[] key)
        {
            // Create a TDES algorithm
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                // Set key, IV, padding mode, and cipher mode for the TDES algorithm
                tdesAlg.Key = key;
                tdesAlg.IV = new byte[8]; // 64 bits (8 bytes)
                tdesAlg.Padding = PaddingMode.Zeros;
                tdesAlg.Mode = CipherMode.ECB;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = tdesAlg.CreateEncryptor();

                // Create a memory stream to store the encrypted data
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Create a CryptoStream to write the encrypted data to the memory stream
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        // Create a StreamWriter to write the plaintext to the CryptoStream
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        private void Button5_Click(object sender, RoutedEventArgs e)
        {
            string plainText = textBox9.Text;
            byte[] Key = Encoding.UTF8.GetBytes(textBox10.Text);
            byte[] encryptedData = EncryptTDes(plainText, Key);

            string Encode = selectionBox3.SelectedItem.ToString();

            switch (Encode)
            {
                // Convert the encrypted bytes to a Base64 string
                case "BASE64":
                    textBox11.Text = Convert.ToBase64String(encryptedData);
                    break;
                // Convert the encrypted bytes to a hexadecimal string without dashes
                case "Hexadecimal":
                    textBox11.Text = BitConverter.ToString(encryptedData).Replace("-", "");
                    break;
                // Throw an exception if the encoding format is invalid
                default:
                    throw new ArgumentException("Invalid encoding format");
            }
        }

        private void SecretKeyTDES_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 24)
            {
                // If the text length exceeds 24 characters, trim it to 24 characters
                textBox.Text = textBox.Text.Substring(0, 24);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private byte[] DecryptTDes(byte[] cipherText, byte[] key)
        {
            // Create a TDES algorithm
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                // Set key, IV, padding mode, and cipher mode for the TDES algorithm
                tdesAlg.Key = key;
                tdesAlg.IV = new byte[8];
                tdesAlg.Padding = PaddingMode.Zeros;
                tdesAlg.Mode = CipherMode.ECB;

                //Create an decryptor using the key and IV
                ICryptoTransform decryptor = tdesAlg.CreateDecryptor();

                byte[] decryptedBytes;

                //Create a memory stream from the input ciphertext byte array
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    //Create a CryptoStream to read the decrypted data from the memory stream
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Create a memory stream to store the decrypted result
                        using (MemoryStream msResult = new MemoryStream())
                        {
                            csDecrypt.CopyTo(msResult);
                            decryptedBytes = msResult.ToArray();
                        }
                    }
                }
                return decryptedBytes;
            }
        }

        private string TDES(string cipherText, byte[] Key)
        {
            string Encode = selectionBox3.SelectedItem.ToString();
            byte[] encryptedData;

            if (Encode == "BASE64")
            {
                // Convert Base64 input to byte array
                encryptedData = Convert.FromBase64String(cipherText);
            }
            else if (Encode == "Hexadecimal")
            {
                // Convert hexadecimal input to byte array
                encryptedData = ConvertHexStringToByteArray(cipherText);
            }
            else
            {
                // Handle invalid encoding selection
                throw new ArgumentException("Invalid encoding selected");
            }
            byte[] decryptedData = DecryptTDes(encryptedData, Key);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            return decryptedText;
        }

        private void Button6_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = textBox11.Text;
            byte[] Key = Encoding.UTF8.GetBytes(textBox10.Text);
            string decryptedText = TDES(cipherText, Key);

            // Display the decrypted text
            textBox12.Text = decryptedText;
        }

        // Prove that 3 x DES = TDES
        private byte[] cipherText2;
        private void Button7_Click(object sender, RoutedEventArgs e)
        {
            Key1 = Encoding.UTF8.GetBytes(textBox14.Text);

            string plainText = textBox13.Text;

            byte[] encryptedData = EncryptDes(plainText, Key1);

            textBox15.Text = Convert.ToBase64String(encryptedData);
        }

        private void Button8_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = textBox15.Text;
            Key2 = Encoding.UTF8.GetBytes(textBox16.Text);

            byte[] encryptedData = Convert.FromBase64String(cipherText);
            byte[] decryptedData = DecryptDes(encryptedData, Key2);

            cipherText2 = decryptedData;

            textBox17.Text = Convert.ToBase64String(decryptedData);
        }

        private byte[] EncryptDes(byte[] plainBytes, byte[] key)
        {
            // Create an DES algorithm
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                // Set key, IV, padding mode, and cipher mode for the DES algorithm
                desAlg.Key = key;
                desAlg.IV = new byte[8];
                desAlg.Padding = PaddingMode.Zeros;
                desAlg.Mode = CipherMode.ECB;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = desAlg.CreateEncryptor();

                byte[] encryptedBytes;

                // Create a memory stream to store the encrypted data
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Create a CryptoStream to write the encrypted data to the memory stream
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }
                return encryptedBytes;
            }
        }

        private void Button9_Click(object sender, RoutedEventArgs e)
        {
            Key3 = Encoding.UTF8.GetBytes(textBox18.Text);

            byte[] encryptedData = EncryptDes(cipherText2, Key3);

            textBox19.Text = Convert.ToBase64String(encryptedData);
        }

        private void Button10_Click(object sender, RoutedEventArgs e)
        {
            string cipherText3 = textBox20.Text;
            Key3 = Encoding.UTF8.GetBytes(textBox21.Text);

            byte[] encryptedData = Convert.FromBase64String(cipherText3);
            byte[] decryptedData = DecryptDes(encryptedData, Key3);
            cipherText2 = decryptedData;

            textBox22.Text = Convert.ToBase64String(decryptedData);
        }

        private void Button11_Click(object sender, RoutedEventArgs e)
        {
            byte[] encryptedData = EncryptDes(cipherText2, Key2);

            textBox24.Text = Convert.ToBase64String(encryptedData);
        }

        private void Button12_Click(object sender, RoutedEventArgs e)
        {
            string secondResult = textBox24.Text;
            Key1 = Encoding.UTF8.GetBytes(textBox25.Text);

            byte[] encryptedData = Convert.FromBase64String(secondResult);
            byte[] decryptedData = DecryptDes(encryptedData, Key1);

            string originalPlainText = Encoding.UTF8.GetString(decryptedData);
            textBox26.Text = originalPlainText;
        }

        private void TB14_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 8)
            {
                // If the text length exceeds 8 characters, trim it to 8 characters
                textBox.Text = textBox.Text.Substring(0, 8);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private void TB16_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 8)
            {
                // If the text length exceeds 8 characters, trim it to 8 characters
                textBox.Text = textBox.Text.Substring(0, 8);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private void TB18_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 8)
            {
                // If the text length exceeds 8 characters, trim it to 8 characters
                textBox.Text = textBox.Text.Substring(0, 8);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private void TB21_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 8)
            {
                // If the text length exceeds 8 characters, trim it to 8 characters
                textBox.Text = textBox.Text.Substring(0, 8);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private void TB23_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 8)
            {
                // If the text length exceeds 8 characters, trim it to 8 characters
                textBox.Text = textBox.Text.Substring(0, 8);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }

        private void TB25_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;
            if (textBox.Text.Length > 8)
            {
                // If the text length exceeds 8 characters, trim it to 8 characters
                textBox.Text = textBox.Text.Substring(0, 8);
                textBox.Select(textBox.Text.Length, 0); // Move cursor to the end
            }
        }
        // Hashing
        private string ComputeSha256Hash(string password)
        {
            // Create a SHA256
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));

                // Convert byte array to a string
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private void ButtonSHA256_Click(object sender, RoutedEventArgs e)
        {
            string input = hashbox1.Text;
            string output = ComputeSha256Hash(input);

            hashbox3.Text = output;
        }

        private string ComputeMD5Hash(string password)
        {
            // Create a new instance of the MD5CryptoServiceProvider object.
            MD5 md5Hasher = MD5.Create();

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hasher.ComputeHash(Encoding.Default.GetBytes(password));

            // Create a new Stringbuilder to collect the bytes and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }
            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        private void ButtonMD5_Click(object sender, RoutedEventArgs e)
        {
            string input = hashbox1.Text;
            string output = ComputeMD5Hash(input);

            hashbox2.Text = output;
        }
        private string createSalt(int size)
        {
            var rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
            var buff = new byte[size];
            rng.GetBytes(buff);
            return Convert.ToBase64String(buff);
        }

        private string GenerateSHA256_Salt(string password, string salt)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(password + salt);
            System.Security.Cryptography.SHA256Managed SHA256 = new System.Security.Cryptography.SHA256Managed();
            byte[] hash = SHA256.ComputeHash(bytes);

            return byteArrayToString(hash);
        }

        private string GenerateMD5_Salt(string password, string salt)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(password + salt);
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(bytes);
                return byteArrayToString(hash);
            }
        }

        public static string byteArrayToString(byte[] inputArray)
        {
            StringBuilder output = new StringBuilder("");
            for (int i = 0; i < inputArray.Length; i++)
            {
                output.Append(inputArray[i].ToString("X2"));
            }
            return output.ToString();
        }

        private void ButtonSaltSHA_Click(object sender, RoutedEventArgs e)
        {
            string salt = hashbox4.Text;
            string password = GenerateSHA256_Salt(hashbox1.Text, salt);

            hashbox6.Text = password;
        }

        private void ButtonSaltMD_Click(object sender, RoutedEventArgs e)
        {
            string salt = hashbox4.Text;
            string password = GenerateMD5_Salt(hashbox1.Text, salt);

            hashbox5.Text = password;
        }

        private void ShowSalt(object sender, RoutedEventArgs e)
        {
            string salt = createSalt(10);
            hashbox4.Text = salt;
        }
    }
}
