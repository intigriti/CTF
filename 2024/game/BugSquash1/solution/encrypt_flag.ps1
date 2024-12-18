# Generate a random 32-byte (256-bit) key
$key = [byte[]]::new(32)
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)

# Generate a random 16-byte (128-bit) IV
$iv = [byte[]]::new(16)
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($iv)

# Save the key and IV to files
$keyFilePath = "C:\Users\cat\Desktop\keyfile.key"
$ivFilePath = "C:\Users\cat\Desktop\ivfile.iv"
[System.IO.File]::WriteAllBytes($keyFilePath, $key)
[System.IO.File]::WriteAllBytes($ivFilePath, $iv)

# Specify input and output files
$inputFilePath = "C:\Users\cat\Desktop\flag.png"
$outputFilePath = "C:\Users\cat\Desktop\encrypted_flag.png.enc"

# Create an AES object with the key and IV
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $iv
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

# Encrypt the file
$encryptor = $aes.CreateEncryptor()
$inputBytes = [System.IO.File]::ReadAllBytes($inputFilePath)
$outputStream = [System.IO.File]::OpenWrite($outputFilePath)
$cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outputStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
$cryptoStream.Write($inputBytes, 0, $inputBytes.Length)
$cryptoStream.Close()
$outputStream.Close()

Write-Output "Encryption completed. Encrypted file saved at $outputFilePath"
