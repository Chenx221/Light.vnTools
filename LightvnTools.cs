using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ICSharpCode.SharpZipLib.Zip;
using MimeDetective;

namespace LightvnTools
{
    public class LightvnTools
    {
        static readonly string VERSION = "1.2.0";

        // PKZip signature
        static readonly byte[] PKZIP = { 0x50, 0x4B, 0x03, 0x04 };

        // Key used to XOR the file header and footer (reverse)
        // Text: `d6c5fKI3GgBWpZF3Tz6ia3kF0`
        // Source: https://github.com/morkt/GARbro/issues/440
        static readonly byte[] KEY = { 0x64, 0x36, 0x63, 0x35, 0x66, 0x4B, 0x49, 0x33, 0x47, 0x67, 0x42, 0x57, 0x70, 0x5A, 0x46, 0x33, 0x54, 0x7A, 0x36, 0x69, 0x61, 0x33, 0x6B, 0x46, 0x30 };
        static readonly byte[] REVERSED_KEY = { 0x30, 0x46, 0x6B, 0x33, 0x61, 0x69, 0x36, 0x7A, 0x54, 0x33, 0x46, 0x5A, 0x70, 0x57, 0x42, 0x67, 0x47, 0x33, 0x49, 0x4B, 0x66, 0x35, 0x63, 0x36, 0x64 };

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine($"Light.vnTools v{VERSION}");
                Console.WriteLine();
                Console.WriteLine(
                    "Light.vnTools is an unpack and repacking tool for game made with Light.vn game engine (lightvn.net)."
                );
                Console.WriteLine();
                Console.WriteLine("Usage:");
                Console.WriteLine("  Unpack: -u (-r) <folder>");
                Console.WriteLine("  Repack: -p <folder> (-k)");
                Console.ReadKey();
                return;
            }
            string operation = args[0];
            string zipPassword = Encoding.UTF8.GetString(KEY);
            bool recoverFileType = (args[1] == "-r") ? true : false;

            if (operation == "-u") // Unpack
            {
                int a = recoverFileType ? 2 : 1;
                if (Directory.Exists(args[a]))
                {
                    var outputDirectory = Path.Combine(Path.GetDirectoryName(args[a]), "output");

                    if (!Directory.Exists(outputDirectory))
                    {
                        Directory.CreateDirectory(outputDirectory);
                    }

                    var Inspector = new ContentInspectorBuilder()
                    {
                        Definitions = new MimeDetective.Definitions.ExhaustiveBuilder()
                        {
                            UsageType = MimeDetective.Definitions.Licensing.UsageType.PersonalNonCommercial
                        }.Build()
                    }.Build();

                    var files = Directory.GetFiles(args[a]);

                    foreach (var file in files)
                    {
                        if (IsVndat(file))
                        {
                            UnpackVndat(file, Path.Combine(outputDirectory, Path.GetFileNameWithoutExtension(file)), zipPassword);
                        }
                        else if (Path.GetExtension(file).Contains("mcdat"))
                        {
                            Console.WriteLine($"Decrypting {file}...");
                            if (recoverFileType)
                            {
                                string recoveredFileName = Path.Combine(outputDirectory, Path.GetFileNameWithoutExtension(file) + ".");
                                XOR(file, Inspector, recoveredFileName);
                            }
                            else
                            {
                                string decryptedFileName = Path.Combine(outputDirectory, Path.GetFileName(file) + ".dec");
                                XOR(file, decryptedFileName);
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"Directory not found: {args[a]}");
                }
            }
            else if (operation == "-p") // Pack
            {
                if (Directory.Exists(args[1]))
                {
                    var packDirectory = Path.Combine(Path.GetDirectoryName(args[1]), "pack");

                    if (!Directory.Exists(packDirectory))
                    {
                        Directory.CreateDirectory(packDirectory);
                    }

                    string[] files = Directory.GetFiles(args[1]);
                    string[] directories = Directory.GetDirectories(args[1]);

                    // mcdat
                    foreach (string file in files)
                    {
                        string fileName = Path.GetFileName(file);

                        if (Regex.IsMatch(fileName, @"^\d+\.mcdat\.dec$") ||
    (Regex.IsMatch(fileName, @"^\d+\.\w+$") && !fileName.EndsWith(".mcdat", StringComparison.OrdinalIgnoreCase)))
                        {
                            Console.WriteLine($"Pack mcdat file: {file}");
                            string numberPart = Regex.Match(fileName, @"^\d+").Value;
                            string decryptedFileName = Path.Combine(packDirectory, numberPart + ".mcdat");
                            XOR(file, decryptedFileName);
                        }
                    }

                    // vndat
                    foreach (string directory in directories)
                    {
                        Console.WriteLine($"Found directory: {directory}");
                        string outputFile = Path.Combine(packDirectory, Path.GetFileName(directory) + ".vndat");
                        if (args.Length < 3) //no pwd
                        {
                            RepackVndat(directory, outputFile);
                        }
                        else if (args[2] == "-k") //pwd
                        {
                            RepackVndat(directory, outputFile, zipPassword);
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"Directory not found: {args[1]}");
                }
            }
            else
            {
                Console.WriteLine($"Invalid operation: {operation}. Use -u for unpack and -p for pack.");
            }

            Console.WriteLine("\nDone.");
            Console.ReadKey();
            return;
        }

        /// <summary>
        /// Extract `.vndat` file.
        /// </summary>
        /// <param name="vndatFile"></param>
        /// <param name="outputFolder"></param>
        /// <param name="password"></param>
        static void UnpackVndat(string vndatFile, string outputFolder, string? password = "")
        {
            bool usePassword = IsPasswordProtectedZip(vndatFile);

            using ZipFile zipFile = new(vndatFile);
            Directory.CreateDirectory(outputFolder);

            // Old Light.vn encrypt the `.vndat` file with `KEY` as the password.
            if (usePassword)
            {
                Console.WriteLine($"{Path.GetFileName(vndatFile)} are password protected. Using `{password}` as the password.");
                zipFile.Password = password;
            }

            if (zipFile.Count > 0)
            {
                Console.WriteLine($"Extracting {Path.GetFileName(vndatFile)}...");

                foreach (ZipEntry entry in zipFile)
                {
                    string? entryPath = Path.Combine(outputFolder, entry.Name);
                    Directory.CreateDirectory(Path.GetDirectoryName(entryPath));

                    if (!entry.IsDirectory)
                    {
                        try
                        {
                            Console.WriteLine($"Writing {entryPath}...");
                            using Stream inputStream = zipFile.GetInputStream(entry);
                            using FileStream outputStream = File.Create(entryPath);

                            if (usePassword)
                            {
                                inputStream.CopyTo(outputStream);
                            }
                            else
                            {
                                using MemoryStream memoryStream = new();
                                inputStream.CopyTo(memoryStream);
                                byte[] buffer = XOR(memoryStream.ToArray());
                                outputStream.Write(buffer, 0, buffer.Length);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to write {entryPath}! {ex.Message}");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Archive folder as `.vndat` file.
        /// </summary>
        /// <param name="sourceFolder"></param>
        /// <param name="password"></param>
        static void RepackVndat(string sourceFolder, string outputFile, string? password = "")
        {
            string[] files = GetFilesRecursive(sourceFolder);
            string? tempFolder = $"{sourceFolder}_temp";
            if (Directory.Exists(tempFolder))
            {
                Directory.Delete(tempFolder, true);
            }
            bool usePassword = !string.IsNullOrEmpty(password);

            using ZipOutputStream zipStream = new(File.Create(outputFile));
            zipStream.SetLevel(0);
            // Uses the backup file to check if it's encrypted to bypass
            // the file is being used by another process exception.
            if (usePassword)
            {
                Console.WriteLine($"Encrypting {Path.GetFileName(outputFile)} using `{password}` as the password...");
                zipStream.Password = password;
            }
            else
            {
                Console.WriteLine($"Creating a temporary copy of {Path.GetFileName(sourceFolder)} to perform XOR encryption...");

                foreach (string file in files)
                {
                    string tempFilePath = Path.Combine(tempFolder, Path.GetRelativePath(sourceFolder, file));
                    string directory = Path.GetDirectoryName(tempFilePath);
                    if (!Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }
                    byte[] processedData = XOR(File.ReadAllBytes(file));
                    File.WriteAllBytes(tempFilePath, processedData);
                    files = GetFilesRecursive(tempFolder);
                }
            }

            Console.WriteLine($"Creating {outputFile} archive...");

            foreach (string filePath in files)
            {
                FileInfo file = new(filePath);
                // Keep file structure by including the folder
                string entryName = filePath[usePassword ? sourceFolder.Length.. : tempFolder.Length..].TrimStart('\\');
                ZipEntry entry = new(entryName)
                {
                    DateTime = DateTime.Now,
                    Size = file.Length
                };
                zipStream.PutNextEntry(entry);

                using FileStream fileStream = file.OpenRead();
                byte[] buffer = new byte[8192]; // Optimum size
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    zipStream.Write(buffer, 0, bytesRead);
                }
            }

            if (!usePassword)
            {
                Console.WriteLine("Cleaning up temporary files...");
                Directory.Delete(tempFolder, true);
            }

            Console.WriteLine("Done.");
        }

        /// <summary>
        /// Check if the given file is `.vndat` file (Zip) or not.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        static bool IsVndat(string filePath)
        {
            try
            {
                byte[] fileSignature = new byte[4];

                using FileStream file = File.OpenRead(filePath);
                file.Read(fileSignature, 0, fileSignature.Length);

                for (int i = 0; i < fileSignature.Length; i++)
                {
                    if (fileSignature[i] != PKZIP[i])
                        return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading {Path.GetFileName(filePath)}. {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Check if the ZIP file is password protected.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        static bool IsPasswordProtectedZip(string filePath)
        {
            try
            {
                using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read);
                using ZipInputStream zipStream = new(fileStream);

                ZipEntry entry;
                while ((entry = zipStream.GetNextEntry()) != null)
                {
                    if (entry.IsCrypted)
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// XOR <paramref name="buffer"/> data.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        static byte[] XOR(byte[] buffer)
        {
            if (buffer.Length < 100)
            {
                if (buffer.Length <= 0)
                    return buffer;

                // XOR entire bytes
                for (int i = 0; i < buffer.Length; i++)
                    buffer[i] ^= REVERSED_KEY[i % KEY.Length];
            }
            else
            {
                // XOR the first 100 bytes
                for (int i = 0; i < 100; i++)
                    buffer[i] ^= KEY[i % KEY.Length];

                // XOR the last 100 bytes
                for (int i = 0; i < 99; i++)
                    buffer[buffer.Length - 99 + i] ^= REVERSED_KEY[i % KEY.Length];
            }

            return buffer;
        }

        /// <summary>
        /// Do XOR operation on the <paramref name="filePath"/>.
        /// </summary>
        /// <param name="filePath"></param>
        static void XOR(string filePath, string? outputFilePath = null)
        {
            try
            {
                byte[] buffer;
                int bufferLength;

                using FileStream inputStream = File.OpenRead(filePath);
                buffer = new byte[bufferLength = (int)inputStream.Length];
                inputStream.Read(buffer, 0, bufferLength);

                buffer = XOR(buffer);

                using FileStream outputStream = File.OpenWrite(outputFilePath ?? filePath);
                outputStream.Write(buffer, 0, bufferLength);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        static void XOR(string filePath, ContentInspector Inspector, string? outputFilePath = null)
        {
            try
            {
                byte[] buffer;
                int bufferLength;

                using FileStream inputStream = File.OpenRead(filePath);
                buffer = new byte[bufferLength = (int)inputStream.Length];
                inputStream.Read(buffer, 0, bufferLength);

                buffer = XOR(buffer);

                var Results = Inspector.Inspect(buffer);
                if (Results.Length == 0)
                {
                    outputFilePath += "dec";
                }
                else
                {
                    outputFilePath += Results[0].Definition.File.Extensions[0];
                }


                using FileStream outputStream = File.OpenWrite(outputFilePath ?? filePath);
                outputStream.Write(buffer, 0, bufferLength);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        /// <summary>
        /// Get all files from a folder.
        /// </summary>
        /// <param name="sourceFolder"></param>
        /// <returns>File paths.</returns>
        static string[] GetFilesRecursive(string sourceFolder)
        {
            return Directory.GetFiles(sourceFolder, "*.*", SearchOption.AllDirectories);
        }

        /// <summary>
        /// Copy entire files in a folder.
        /// </summary>
        /// <param name="sourceDirectory"></param>
        /// <param name="destinationDirectory"></param>
        static void CopyFolder(string sourceDirectory, string destinationDirectory)
        {
            if (!Directory.Exists(destinationDirectory))
                Directory.CreateDirectory(destinationDirectory);

            string[] files = GetFilesRecursive(sourceDirectory);

            foreach (string sourceFilePath in files)
            {
                string relativePath = sourceFilePath[sourceDirectory.Length..].TrimStart('\\');
                string destinationFilePath = Path.Combine(destinationDirectory, relativePath);

                string destinationFileDirectory = Path.GetDirectoryName(destinationFilePath);
                if (!Directory.Exists(destinationFileDirectory))
                    Directory.CreateDirectory(destinationFileDirectory);

                File.Copy(sourceFilePath, destinationFilePath, true);
            }
        }
    }
}
