package mySNS_1fase;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class MySNS {

	static ObjectInputStream in;
	static ObjectOutputStream out;
	static Socket echoSocket;
	static Scanner scanner = new Scanner(System.in);
	static String keystorePassword;
	static String keystorePath;

	public static void main(String[] args) throws Exception {
		
		System.setProperty("javax.net.ssl.trustStore", "truststore.client"); 
		System.setProperty("javax.net.ssl.trustStorePassword", "123456");

		String serverAddress = null;
		String doctorUsername = null;
		String patientUsername = null;
		String action = null;
		String[] filenames = null;
		/* trab 2 */
		String username = null;
		String password = null;
		
		// Prints the number of arguments
		System.out.println("Número de argumentos da linha de comando: " + args.length);
		for (String arg : args) {
			// Prints each argument
			System.out.println("Argumento: " + arg);
		}

		try {
			if (args[0].equals("mySNS") && args[1].equals("-a")) {
				serverAddress = args[2];

				if (args.length < 4) {
					System.err.println("Número insuficiente de argumentos. Use '-u', '-m' ou '-au' depois de <serverAddress>.");
					return;
				}

				switch (args[3]) {
					case "-m":
						if (args.length < 11) {
							System.err.println("Número insuficiente de argumentos para o modo médico '-m'.");
							return;
						}
						doctorUsername = args[4];
						if (!args[5].equals("-p")) {
							System.err.println(
									"Formato inválido para a password '-p'. Use '-p' depois do nome de médico.");
							return;
						}
						password = args[6];

						if (!args[7].equals("-u")) {
							System.err.println(
									"Formato inválido para a opção -u. Use '-u' para o username do utente depois de '-m'.");
							return;
						}
						patientUsername = args[8];

						action = args[9];

						// Check if the action is one of the valid options
						if (!action.equals("-sc") && !action.equals("-sa") && !action.equals("-se")) {
							System.err.println("Opção inválida. Use '-sc', '-sa', ou '-se'.");
							return;
						}
						filenames = new String[args.length - 10];
						System.arraycopy(args, 10, filenames, 0, args.length - 10);

						break;
					case "-u":
						if (args.length < 9) {
							System.err.println("Número de argumentos inválidos para o modo utente (-u).");
							return;
						}
						patientUsername = args[4];
						if (!args[5].equals("-p")) {
							System.err.println(
									"Formato inválido para a password '-p'.");
							return;
						}

						password = args[6];

						if (!args[7].equals("-g")) {
							System.err.println(
									"Formato inválido para a opção -g. Use '-g' seguido do username do utente depois de '-u'.");
							return;
						}

						action = args[7];
						filenames = new String[args.length - 8];
						System.arraycopy(args, 8, filenames, 0, args.length - 8);

						break;

					case "-au":
						if (args.length < 7) {
							System.err.println("Número de argumentos inválidos para a criação de utilizadores '-au'.");
							return;
						}
						username = args[4];
						password = args[5];
						filenames = new String[args.length - 6];
						System.arraycopy(args, 6, filenames, 0, args.length - 6);

						break;
					default:
						System.err.println(
								"Formato inválido: Use '-m' para o username do médico, e '-u' para o username do utente ou '-au' para criação de utilizadores depois de <serverAddress>");
						return;
				}
				
				// Check if the files exist
				boolean filesMissing = false;    
				for (String filename : filenames) {
					File file = new File(filename);
					if (!file.exists()) {
						System.err.println("Ficheiro: '" + filename + "' não existe no cliente.");
						filesMissing = true; // True if any file is missing
					}
				}

				// If any files are missing, provide feedback and return
//				if (filesMissing) {
//					System.out.println(22);
//				}
			}else {
				System.err.println("Erro no comando. Certifique-se que tem '-a' após o 'mySNS'.");
				System.exit(-1);
			}

			
		} catch (ArrayIndexOutOfBoundsException e) {
			System.err.println("Número de argumentos inválidos ou formato inválido de argumentos.");

			return;
		}

		try {
			// Socket(ip adress, port)
			SocketFactory sf = SSLSocketFactory.getDefault( ); // Socket SSL
			echoSocket = sf.createSocket(serverAddress.split(":")[0], Integer.parseInt(serverAddress.split(":")[1]));
			System.out.println("Endereço IP: " + serverAddress.split(":")[0]);
			System.out.println("Conectado ao servidor: " + Integer.parseInt(serverAddress.split(":")[1]));

			// Creates stream input and output objects
			in = new ObjectInputStream(echoSocket.getInputStream());
			out = new ObjectOutputStream(echoSocket.getOutputStream());
			System.out.println("Verificando os ficheiros: " + Arrays.toString(filenames));

			out.writeObject(doctorUsername);
			out.writeObject(patientUsername);
			out.writeObject(filenames);
			out.writeObject(username);
			out.writeObject(password);

			Object response = in.readObject();

			// Handle the server response
			if (response instanceof String) {
				String message = (String) response;
				if (message.startsWith("Erro")) {
					// Error message from the server
					System.err.println("Erro do servidor: " + message);
					System.exit(-1);
				} else {
					// Success message from the server
					System.out.println("Mensagem de sucesso do servidor: " + message);
				}
			} else {
				System.err.println("Resposta inesperada do servidor");
			}

			// Create patient directory if it doesn't exist yet
			if (patientUsername != null) {
				Path patientDirectory = Paths.get("cliente", patientUsername);
				if (!Files.exists(patientDirectory)) {
					Files.createDirectories(patientDirectory);
					// Create upload and download directories inside patient's directory
					Path uploadDirectory = patientDirectory.resolve("upload");
					Path downloadDirectory = patientDirectory.resolve("download");
					Files.createDirectories(uploadDirectory);
					Files.createDirectories(downloadDirectory);
				}
			}

			// Create doctor directory if it doesn't exist yet
			if (doctorUsername != null) {
				if (doctorUsername != null) {
					Path doctorDirectory = Paths.get("cliente", doctorUsername);
					if (!Files.exists(doctorDirectory)) {
						Files.createDirectories(doctorDirectory);
					}
				}
			}

			// Mode: doctor or patient
			String mode = null;
			if (args[3].equals("-m")) {
				mode = "medico";
			} else if (args[3].equals("-u")) {
				mode = "utente";
			}

			if (!args[3].equals("-au")) {
				// Keystore file paths based on the mode
				File keystoreFile = null;
				if (mode.equals("medico")) {
					System.out.println("Modo " + mode);
					if (doctorUsername == null) {
						System.err.println("Username do médico não especificado.");
						return;
					}
					keystoreFile = new File("cliente/" + doctorUsername + "/" + doctorUsername + ".keystore");
				} else if (mode.equals("utente")) {
					System.out.println("Modo " + mode);
					if (patientUsername == null) {
						System.err.println("Username do utente não especificado.");
						return;
					}
					keystoreFile = new File("cliente/" + patientUsername + "/" + patientUsername + ".keystore");
				}

				// Verify if the keystore file already exists
				if (!verifyKeystoreFile(keystoreFile)) {
					String errorMessage = "";
					errorMessage = "Erro: O ficheiro da keystore: " + keystoreFile + " não foi encontrado. Por favor importe o ficheiro para " + "se conectar ao servidor.";
					out.writeObject(errorMessage);
					out.flush();
					System.err.println(errorMessage);
					System.exit(-1);
				}

				// Store patient's keystore path in the global variable
				keystorePath = keystoreFile.getAbsolutePath();

				// Get keystore password from user input if the keystore file exists
				System.out.print("Por favor, insira a password da keystore: ");
				keystorePassword = scanner.nextLine();

				// Verify keystore password before proceeding
				if (verifyKeystorePassword(keystorePath, keystorePassword)) {
					String message = "Keystore password correta. Prosseguir...";
					String message2 = "";
					
					if(mode.equals("medico")) {

						boolean containsPatientCertificate = containsCertificateWithPatientName(keystorePath, patientUsername, keystorePassword);
						if (containsPatientCertificate) {
							System.out.println("A keystore contém o certificado com o nome do utilizador.");
						} else {
							System.err.println("Erro: Nenhum certificado com o nome do utente foi encontrado na keystore.");

							System.out.println("Importando o certficado do servidor para adicionar a keystore..");
							
							 boolean sucesso = addCertificate(patientUsername, keystorePath, keystorePassword, in, out);
						        if (sucesso) {
						            System.out.println("Certificado adicionado com sucesso!");
						        } else {
						            message2="Erro: Falha ao adicionar o certificado.";
						            out.writeObject(message2);
									out.flush();
									System.out.println(message2);
						            System.exit(-1);
						        }
						}
						
			
					}else {
						String medico = (String) in.readObject();
						System.out.println("MEDICO NOMEE: " + medico);
						
					    boolean certificateNeeded = false; 

					   
						
						boolean containsPatientCertificate = containsCertificateWithPatientName(keystorePath, medico, keystorePassword);
						if (containsPatientCertificate) {
							System.out.println("A keystore contém o certificado com o nome do utilizador.");
							certificateNeeded = false;
							 out.writeObject(certificateNeeded);
							 out.flush();
							 System.err.println(certificateNeeded);
						} else {
							System.err.println("Erro: Nenhum certificado com o nome do medico foi encontrado na keystore.");

							System.out.println("Importando o certficado do servidor para adicionar a keystore..");
							certificateNeeded = true;
							 out.writeObject(certificateNeeded);
							 out.flush();
							 System.err.println(certificateNeeded);
							 boolean sucesso = addCertificate(medico, keystorePath, keystorePassword, in, out);
						        if (sucesso) {
						            System.out.println("Certificado adicionado com sucesso!");
						        } else {
						            message2="Erro: Falha ao adicionar o certificado.";
						            out.writeObject(message2);
									out.flush();
									System.out.println(message2);
						            System.exit(-1);
						        }
						}
						
					}
					out.writeObject(message);
					out.flush();
					System.out.println(message);
				} 
				
				else {
					String fileName = new File(keystorePath).getName();
					String message = "Erro: Password incorreta para a keystore:  "
							+ fileName + ". Por favor forneça a password correta para se conectar ao servidor.";

					out.writeObject(message);
					out.flush();
					System.err.println(message);
					return;
				}
			}

			// Iterates through files to check if they exist. If they do, performs actions
			// based on the options -sc, -sa, -se and -g
			for (String filename : filenames) {
				File file = new File(filename);
				System.out.println("Verificando o ficheiro: " + file.getAbsolutePath());

				// Checks file existence
				if(args[3]=="m") {
					if (!file.exists()) {
						System.out.println("O ficheiro '" + filename + "' não foi encontrado. Será omitido...");
						continue;
					}
				}

				/* Paths to the specific files: */
				// name of encrypted file
				String encryptedFileName = "cliente/" + patientUsername + "/upload/" + filename + ".cifrado";
				// secret key
				String chaveSecreta = "cliente/" + patientUsername + "/upload/" + filename + ".chave_secreta."
						+ patientUsername;
				// name of the signature file
				String signatureFileName = "cliente/" + patientUsername + "/upload/" + filename + ".assinatura."
						+ doctorUsername;
				// name of the signed file for -sa
				String signedFileName = "cliente/" + patientUsername + "/upload/" + filename + ".assinado";
				// name of the signed file for -se
				String seguroFileName = "cliente/" + patientUsername + "/upload/" + filename + ".seguro";

				switch (args[3]) {

					case "-m":
						// Option -sc -> encrypts files and sends them to the server
						if (args[9].equals("-sc")) {

							// files to send to the server
							String[] filesToSend = new String[] { encryptedFileName, chaveSecreta };

							try {
								Certificate cert = getCertificateFromKeystore(keystorePath, keystorePassword,
										patientUsername);
								if (cert != null) {

									encryptFile(file, encryptedFileName, patientUsername, cert);

									sendServer(filesToSend, out, in);
								} else {
									System.out.println("Erro ao extrair o certificado.");
								}

							} catch (Exception e) {

								System.err.println("Erro ao cifrar o ficheiro: " + e.getMessage());

								return;
							}
						}
						// Option -sa -> signs files and sends them to the server
						else if (args[9].equals("-sa")) {

							// Files to send to the server
							String[] filesToSend = new String[] { signatureFileName, signedFileName };

							try {
								// Obtain the private key after verifying the keystore password
								PrivateKey myPrivateKey = getPrivateKey(doctorUsername, keystorePassword);
								if (myPrivateKey != null) {
									signFile(file, signatureFileName, myPrivateKey);
									readWrite(file, signedFileName);
									sendServer(filesToSend, out, in);
								} else {
									System.out.println("Erro na chave secreta");
								}
							} catch (Exception e) {
								System.err.println("Erro ao assinar o ficheiro: " + e.getMessage());

								return;
							}
						}

						// Option -se -> signs and encrypts files and sends them to the server
						else if (args[9].equals("-se")) {
							try {

								String[] filesToSend = new String[] { signatureFileName, seguroFileName, chaveSecreta };

								Certificate cert = getCertificateFromKeystore(keystorePath, keystorePassword,
										patientUsername);

								PrivateKey myPrivateKey = getPrivateKey(doctorUsername, keystorePassword);

								if (myPrivateKey != null && cert != null) {

									encryptSignFile(file, signatureFileName, myPrivateKey, seguroFileName, cert,
											patientUsername);
									sendServer(filesToSend, out, in);
								}

							} catch (Exception e) {
								// Print the error message
								System.err.println("Erro ao assinar o ficheiro: " + e.getMessage());
								// Return without calling enviarServidor
								return;
							}
						}

						break;

					case "-u":

						if (args[7].equals("-g")) {

							// All required files exist, proceed with decryption
							try {

								// Obtain the private key after verifying the keystore password
								PrivateKey myPrivateKey = getPrivateKey(patientUsername, keystorePassword);

								String[] filesToSend = new String[] { filename };
								System.out.println(Arrays.toString(filesToSend));

								File decifrado = new File("cliente/" + patientUsername + "/download/" + filename);

								// Check if files already exist in download
								if (checkExistenceFilesDownload(filesToSend, patientUsername) && decifrado.exists()) {
									System.out.println(
											"Os ficheiros cifrado, assinado, chave secreta e decifrado do ficheiro "
													+ filename + " já existem no cliente.");
									String[] noFiles = new String[] { "No files" };
									out.writeObject(noFiles);
									continue;
								}

								System.out.println("Ficheiros a serem enviados: " + Arrays.toString(filesToSend));

								checkExistenceFilesServer(filesToSend, out, in); 
								List<Boolean> recebidos = receiveFilesFromServer(patientUsername, filename);

								// The directory path to upload
								String directoryPath = "cliente/" + patientUsername + "/download/";

								try {
									// se o .cifrado foi recebido
									if (recebidos.get(0)) {

//										// Combine both success messages with a delimiter
//										String combinedSuccessMessage = "rui";
//
//										// Send the combined success message
//										out.writeObject(combinedSuccessMessage);
//										out.flush();
//										System.out.println(combinedSuccessMessage);

										/* Paths to the specific files: */
										// name of encrypted file
										String encryptedFileName2 = "cliente/" + patientUsername + "/download/"
												+ filename + ".cifrado";
										// secret key
										String chaveSecreta2 = "cliente/" + patientUsername + "/download/" + filename
												+ ".chave_secreta."
												+ patientUsername;

										decryptFile(file, encryptedFileName2, chaveSecreta2, patientUsername,
												myPrivateKey);
									}
								} catch (FileNotFoundException e) {
									System.err.println(e.getMessage());
								}

								try {
									// se o assinado foi recebido
									if (recebidos.get(1)) {
										
										// Get doctor username
										// The desired file extension to get the doctor user name
										String desiredExtension = filename + ".assinatura";
										System.out.println(desiredExtension);

										File directory = new File(directoryPath);

										// The signed file
										String signedFile = null;

										// Find the first file with the specified string in its name
										File[] files = directory.listFiles();
										if (files != null) {
											for (File file2 : files) {
												if (file2.isFile() && file2.getName().contains(desiredExtension)) {
													signedFile = file2.getName();
												}
											}
										}

										String[] parts = signedFile.split("\\.");
										String medico = parts[parts.length - 1];
//										System.out.println("med " + medico + " " + filename);
//										
//								        // Send doctor's name to the server
//								        out.writeObject(medico);
//								        out.flush();
//										
										// Retrieve the doctor's certificate
										Certificate cert = getCertificateFromKeystore(keystorePath, keystorePassword,
												medico);

										// name of the signature file
										String signatureFileName2 = "cliente/" + patientUsername + "/download/"
												+ filename
												+ ".assinatura." + medico;
										// name of the signed file
										String signedFileName2 = "cliente/" + patientUsername + "/download/" + filename
												+ ".assinado";
										// name of the original file
										String fileName2 = "cliente/" + patientUsername + "/download/" + filename;

										// Validate signature
										if (validateFile(new File(signedFileName2), signatureFileName2, cert)) {
											readWrite(new File(signedFileName2), fileName2);
										}

									}
								} catch (Exception e) {
									e.printStackTrace();
								}

								try {
									// If ".seguro" was received
									if (recebidos.get(2)) {									
										// Get doctor username
										// The desired file extension to get the doctor user name
										String desiredExtension = filename + ".assinatura";
										System.out.println(desiredExtension);

										File directory = new File(directoryPath);

										// The signed file
										String signedFile = null;

										// Find the first file with the specified string in its name
										File[] files = directory.listFiles();
										if (files != null) {
											for (File file2 : files) {
												if (file2.isFile() && file2.getName().contains(desiredExtension)) {
													signedFile = file2.getName();
												}
											}
										}
										
										String[] parts = signedFile.split("\\.");
										String medico = parts[parts.length - 1];
										
										System.out.println("med " + medico + " " + filename);
										

								        // Send doctor's name to the server
//								        out.writeObject(medico);
//								        out.flush();
//								        
//								        String message2 = "";
//								        boolean containsPatientCertificate = containsCertificateWithPatientName(keystorePath, medico, keystorePassword);
//										if (containsPatientCertificate) {
//											System.out.println("A keystore contém o certificado com o nome do utilizador.");
//										} else {
//											System.out.println("Importando o certficado do servidor para adicionar a keystore..");
//											
//											System.err.println("Erro: Nenhum certificado com o nome do utente foi encontrado na keystore.");
//											
//											 boolean sucesso = addCertificate(medico, keystorePath, keystorePassword, in, out);
//										        if (sucesso) {
//										            System.out.println("Certificado adicionado com sucesso!");
//										        } else {
//										            message2="Erro: Falha ao adicionar o certificado.";
//										            out.writeObject(message2);
//													out.flush();
//													System.out.println(message2);
//										            System.exit(-1);
//										        }
//										}
										
										// Retrieve the doctor's certificate
										Certificate cert = getCertificateFromKeystore(keystorePath, keystorePassword,
												medico);

										/* Paths to the specific files: */
										// name of the signature file
										String signatureFileName2 = "cliente/" + patientUsername + "/download/"
												+ filename
												+ ".assinatura." + medico;
										// name of the signed file for -se
										String seguroFileName2 = "cliente/" + patientUsername + "/download/" + filename
												+ ".seguro";
										// secret key
										String chaveSecreta2 = "cliente/" + patientUsername + "/download/" + filename
												+ ".chave_secreta."
												+ patientUsername;

										// Decrypt and Validate
										decryptFile(file, seguroFileName2, chaveSecreta2, patientUsername,
												myPrivateKey);
										validateFile(file, signatureFileName2, cert);
									}
								} catch (Exception e) {
									e.printStackTrace();
								}

							} catch (FileNotFoundException e) {
								System.err.println(e.getMessage());

							} catch (Exception e) {
								e.printStackTrace();

							}

						}
						break;

					case "-au":
						if (args[3].equals("-au")) {		
							String message = "";
							// Verifica se o arquivo existe no cliente
							File certFile = new File(filename);
							if (certFile.exists()) {
								String owner = getCertificateOwner(filename, username);
						        if (owner != null && !owner.startsWith("Erro:")) {
						        	message = "O proprietário do certificado é: " + owner + ". Enviando para o servidor...";
									out.writeObject(message);
									out.flush();
									System.out.println(message);
						        	sendServer(filenames, out, in);
						        	
						        	Object response2 = in.readObject();

									// Handle the server response
									if (response2 instanceof String) {
										message = (String) response2;
										if (message.startsWith("Erro")) {
											// Error message from the server
											System.err.println("Erro do servidor: " + message);
											System.exit(-1);
										} else {
											// Success message from the server
											System.out.println("Mensagem de sucesso do servidor: " + message);
										}
									} else {
										System.err.println("Resposta inesperada do servidor");
									}
						        } else {
						            System.err.println();
						            String errorMessage = "Erro: O certificado não pertence ao username especificado. Por favor, verifique se o certificado está correto.";
									out.writeObject(errorMessage);
									out.flush();
									System.err.println(errorMessage);
									System.exit(-1);
						        }
							}else {
								// Se o arquivo não existir, trate a situação de acordo
							    String errorMessage = "Erro: O ficheiro do certificado: ' " + certFile + "' não existe no cliente.";
							    out.writeObject(errorMessage);
							    out.flush();
							    System.err.println(errorMessage);
							    System.exit(-1);
							}
						}

						break;
					default:
						System.out.print("Argumentos inválidos");
				}
			}

			out.close();
			in.close();
			echoSocket.close();

		} catch (IOException e) {
			System.err.println("Error ao criar a socket: " + e.getMessage());
			e.printStackTrace();
		}
	}

	/**
	 * Encrypts the specified file using AES encryption and generates a secret key
	 * file
	 * 
	 * @param file              The file to be encrypted
	 * @param encryptedFileName The path where the encrypted file will be saved
	 * @param patientUsername   The user name of the patient
	 * @param cert              The certificate used to wrap the secret key
	 * @throws Exception if an error occurs during the encryption process
	 */
	private static void encryptFile(File file, String encryptedFileName, String patientUsername,
			Certificate cert) throws Exception {

		// Check if the encrypted file already exists
		File existingEncryptedFile = new File(encryptedFileName);
		if (existingEncryptedFile.exists()) {
			System.out.println("O ficheiro " + file + " já está cifrado.");
			return; // Exit the method as the file is already encrypted
		}
		
		// If the file doesn't exist, print a message and continue with the next file
	    if (!file.exists()) {
	        System.out.println("O ficheiro " + file.getName() + " não existe no cliente. Será omitido...");
	        return;
	    }

		try {

			// gerar uma chave aleatoria para utilizar com o AES
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			SecretKey key = kg.generateKey();

			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, key);

			FileInputStream fis;
			FileOutputStream fos;
			CipherOutputStream cos;

			fis = new FileInputStream(file); // fis is never close
			fos = new FileOutputStream(encryptedFileName);

			cos = new CipherOutputStream(fos, c);
			byte[] b = new byte[256];
			int i = fis.read(b);

			while (i != -1) {
				cos.write(b, 0, i);
				i = fis.read(b);
			}
			cos.close();
			fis.close();

			// Encrypt the AES key with the public key
			Cipher c1 = Cipher.getInstance("RSA");
			c1.init(Cipher.WRAP_MODE, cert);
			byte[] keyEncoded = c1.wrap(key);

			String keyName = encryptedFileName.split("\\.")[0] + "." + encryptedFileName.split("\\.")[1]
					+ "." + "chave_secreta" + "." + patientUsername; // relatorio.pdf.chave_secreta.maria

			FileOutputStream kos = new FileOutputStream(keyName);
			kos.write(keyEncoded);
			kos.close();

			System.out.println("O ficheiro foi cifrado com sucesso: " + encryptedFileName);

		} catch (IOException e) {
	        e.printStackTrace();
		}
	}

	/**
	 * Signs the provided file with the given private key and saves the signature to
	 * the specified file
	 *
	 * @param file              The file to be signed
	 * @param signatureFileName The path where the signature will be saved
	 * @param patientUsername   The user name of the patient
	 * @param privateKey        The private key used for signing
	 * @throws Exception If an error occurs during the signing process
	 */
	private static void signFile(File file, String signatureFileName,
			PrivateKey privateKey) throws Exception {

		// If the password is correct, proceed to check if the file is already signed
		File existingSignatureFile = new File(signatureFileName);
		if (existingSignatureFile.exists()) {
			System.out.println("O ficheiro " + file + " já está assinado.");
			return; // Exit the method as the file is already signed
		}
		
		// If the file doesn't exist, print a message and continue with the next file
	    if (!file.exists()) {
	        System.out.println("O ficheiro " + file.getName() + " não existe no cliente. Skipping...");
	        return;
	    }

		try {

			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign((PrivateKey) privateKey);

			FileInputStream fis = new FileInputStream(file);
			byte[] b = new byte[256];
			int i = fis.read(b);
			while (i != -1) {
				s.update(b, 0, i);
				i = fis.read(b);
			}

			fis.close();
			byte[] mySignature = s.sign();

			FileOutputStream sfile = new FileOutputStream(signatureFileName);
			sfile.write(mySignature);
			sfile.close();

			System.out.println("O ficheiro foi assinado com sucesso: " + signatureFileName);

		} catch (IOException e) {
			e.printStackTrace();

		}
	}

	/**
	 * Encrypts and signs a file with the provided parameters
	 *
	 * @param file              The file to be encrypted and signed
	 * @param signatureFileName The name of the file to store the signature
	 * @param privateKey        The private key used for signing
	 * @param cifraFileName     The name of the file to store the encrypted content
	 * @param cert              The certificate used for encryption
	 * @param patientName       The name of the patient associated with the file
	 * @throws Exception If an error occurs during encryption or signing
	 */
	private static void encryptSignFile(File file, String signatureFileName, PrivateKey privateKey,
			String cifraFileName, Certificate cert, String patientName)
			throws Exception {

		try {

			encryptFile(file, cifraFileName, patientName, cert);
			signFile(file, signatureFileName, privateKey);

		} catch (FileNotFoundException e) {

			e.printStackTrace();
		}
	}

	/**
	 * Decrypts a file using the provided secret key and saves the decrypted content
	 * to a new file
	 *
	 * @param file              The file to be decrypted
	 * @param encryptedFileName The name of the encrypted file
	 * @param chave_secreta     The path to the file containing the secret key
	 * @param patientUsername   The user name of the patient
	 * @throws Exception if an error occurs during the decryption process
	 */
	private static void decryptFile(File file, String encryptedFileName,
			String chave_secreta, String patientUsername, Key privateKey) throws Exception {
		// System.out.println("Parou em decryptFile");

		String decryptedFileName1 = encryptedFileName.split("\\/")[3];

		String decryptedFileName2 = decryptedFileName1.split("\\.")[0] + "."
				+ decryptedFileName1.split("\\.")[1];

		String decryptedFilePath = "cliente/" + patientUsername + "/download/" + decryptedFileName2;

		File decryptedFile = new File(decryptedFilePath);
		if (decryptedFile.exists()) {
			System.out.println("O ficheiro decifrado já existe.");
			return;
		}

		// Keystore file exists, proceed with decryption
		try {

			byte[] keyEncoded = new byte[256];
			FileInputStream kfile = new FileInputStream(chave_secreta);
			kfile.read(keyEncoded);
			kfile.close();

			// Encrypt the AES key with the public key
			Cipher c1 = Cipher.getInstance("RSA");
			// System.out.println(55);
			c1.init(Cipher.UNWRAP_MODE, privateKey);
			// System.out.println(66);
			Key aeskey = c1.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);
			// System.out.println(77);

			Cipher c2 = Cipher.getInstance("AES");
			c2.init(Cipher.DECRYPT_MODE, aeskey);

			FileInputStream fis = new FileInputStream(encryptedFileName);

			FileOutputStream fos = new FileOutputStream(decryptedFilePath);

			CipherInputStream cis = new CipherInputStream(fis, c2);

			byte[] b = new byte[256];
			int i = cis.read(b);

			while (i != -1) {
				fos.write(b, 0, i);
				i = cis.read(b);
			}

			cis.close();
			fos.close();
			fis.close();

			System.out.println("O ficheiro foi decifrado com sucesso: " + decryptedFilePath);

		} catch (FileNotFoundException e) {

			e.printStackTrace();
		}
	}

	/**
	 * Validates the signature of a file using the provided certificate
	 *
	 * This method validates the signature of the specified file using the provided
	 * certificate
	 *
	 * @param file            The file to be validated
	 * @param signedFile      The name of the file containing the signature
	 * @param patientUsername The user name of the patient
	 * @throws Exception if an error occurs during the validation process
	 */
	private static Boolean validateFile(File file, String signedFile,
			Certificate cert) throws Exception {

		try {
			System.out.println("Parou em validateFile" + file);

			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(cert);

			FileInputStream fis = new FileInputStream(file);
			byte[] b = new byte[256];
			int i = fis.read(b);
			while (i != -1) {
				s.update(b, 0, i);
				i = fis.read(b);
			}

			fis.close();
			// Read signature from signature file
			byte[] assinatura = new byte[256];
			FileInputStream sfile = new FileInputStream(signedFile);
			sfile.read(assinatura);
			sfile.close();

			boolean res = s.verify(assinatura);
			System.out.println("A assinatura do ficheiro " + file.getName() + " é válida ? --> " + res);

			return res;

		} catch (FileNotFoundException e) {
			if (e.getMessage() != null) {
				System.err.println("FileNotFoundException: Exception message: " + e.getMessage());
				if (e.getMessage().contains(signedFile)) {
					System.err.println(
							"FileNotFoundException: O ficheiro da assinatura " + signedFile + " não foi encontrado.");
				} else {
					System.err.println("FileNotFoundException: Um ficheiro não foi encontrado. Mensagem de erro: "
							+ e.getMessage());
				}
			} else {
				System.err.println("FileNotFoundException: Um ficheiro não foi encontrado.");
			}
		}
		return null;
	}

	/**
	 * Sends files to the server along with a flag indicating whether they should be
	 * encrypted or signed
	 *
	 * @param filenames An array of filenames to send to the server
	 * @param l         A flag indicating whether the files should be encrypted or
	 *                  signed
	 * @param out       The ObjectOutputStream used to send data to the server
	 * @param in        The ObjectInputStream used to receive responses from the
	 *                  server
	 * @throws Exception if an error occurs during the file sending process
	 */
	private static void sendServer(String[] filenames, ObjectOutputStream out,
			ObjectInputStream in) throws Exception {
		try {
			System.out.println("Parou no sendServer");
			for (String filename : filenames) {
				// Send file name
				
				 File fileToSend = new File(filename);
		            
	            // Check if the file exists
	            if (!fileToSend.exists()) {
	                System.out.println("O ficheiro " + filename + " não existe no cliente. Skipping...");
	                continue; // Skip to the next file
	            }

				
				out.writeObject(filename);

//				File fileToSend = new File(filename);
				long size = fileToSend.length();
				out.writeLong(size);

				FileInputStream fileInputStream = new FileInputStream(fileToSend);
				BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);

				byte[] buffer = new byte[256];
				int bytesRead;
				while ((bytesRead = bufferedInputStream.read(buffer)) != -1) {
					out.write(buffer, 0, bytesRead);
				}

				// Flush the output stream to ensure all data is sent
				out.flush();

				// Close streams for this file
				fileInputStream.close();
				bufferedInputStream.close();

				System.out.println("Ficheiro/s " + filename + " enviado/s com sucesso.");
			}

		} catch (IOException e) {
			System.err.println("Erro ao enviar os ficheiros para o servidor: " + e.getMessage());
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * Receives files from the server for the specified patient user name
	 *
	 * @param patientUsername The user name of the patient
	 * @throws IOException If an I/O error occurs while receiving files from the
	 *                     server
	 */
	private static List<Boolean> receiveFilesFromServer(String patientusername, String originalfilename)
			throws IOException, ClassNotFoundException {
		System.out.println("Em receiveFilesFromServer");

		List<Boolean> recebidos = new ArrayList<>();

		// Flags to stop the loop as soon as all files are received
		Boolean cifrado = false;
		Boolean seguro = false;
		Boolean assinado = false;
		Boolean assinatura = false;
		Boolean chaveSecreta = false;
		Boolean temFicheiros = true;
		
		temFicheiros=(Boolean)in.readObject();
		
		try {
			while (!(seguro && chaveSecreta && assinatura) && !(assinado && assinatura) && !(cifrado && chaveSecreta) && temFicheiros) {
				
				try {
					System.out.println("Parou em receiveFilesFromServer");
					// Attempt to receive the filename from the client
					String filename = (String) in.readObject();
					//System.out.println("ficheiros reecebidos do servidor " + filename); // ali abaixo já temos o print do nome do ficheiro em "System.out.println("Recebendo o ficheiro: " + filename);"

					// If no exception is thrown, proceed to receive file data
					long fileSize = in.readLong();

					System.out.println("Recebendo o ficheiro: " + filename);
					System.out.println("Dimensão do ficheiro: " + fileSize);

					// Extracting filename
					String file = "cliente/" + patientusername + "/download/" + filename;

					System.out.println("Caminho do ficheiro: " + file);

					// Check if the file already exists
					File existingFile = new File(file);
					if (existingFile.exists()) {
						System.out.println("O ficheiro '" + filename + "' já existe no cliente. Será omitido...");
						// Consume the incoming data from the stream to discard it
						long bytesSkipped = 0;
						while (bytesSkipped < fileSize) {
							long remainingBytes = fileSize - bytesSkipped;
							int bytesToSkip = (int) Math.min(2048, remainingBytes);
							bytesSkipped += in.skip(bytesToSkip);
						}
						//continue; // Skip to the next file
					}else {
						FileOutputStream fos = new FileOutputStream(file);
						BufferedOutputStream bos = new BufferedOutputStream(fos);

						byte[] buffer = new byte[2];
						int bytesRead;
						while (fileSize > 0
								&& (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, fileSize))) != -1) {
							bos.write(buffer, 0, bytesRead);
							fileSize -= bytesRead;
						}

						bos.close();
						fos.close();
					}

					// Check file type and change the flag accordingly
					if (filename.endsWith(".cifrado")) {
						cifrado = true;
					} else if (filename.endsWith(".seguro")) {
						seguro = true;
					} else if (filename.endsWith(".assinado")) {
						assinado = true;
					} else if (filename.contains(".chave_secreta.")) {
						chaveSecreta = true;
					} else if (filename.contains(".assinatura.")) {
						assinatura = true;
					}


					System.out.println("Ficheiro recebido no cliente");

				} catch (EOFException e) {
					// No more files to receive, break out of the loop
					e.printStackTrace();
					break;
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			throw e;
		}
		if(temFicheiros) {
			recebidos.addAll(Arrays.asList(cifrado, assinado, seguro));
			// cifrado, assinado, seguro
			return recebidos;
		}else {
			System.out.println("Ficheiro "+ originalfilename +" não existe no servidor.");
			return Arrays.asList(false,false,false);
		}
		
	}

	/*
	 * ******************* AUXILIARY METHODS *******************
	 */

	// *********** File keystore handling, existence, password ***********
	/**
	 * Verifies if the keystore file exists for the given patient user name
	 *
	 * @param patientUsername The user name of the patient
	 * @return true if the keystore file exists, false otherwise
	 */
	private static boolean verifyKeystoreFile(File keystoreFile) {

		// Check if the keystore file exists
		if (!keystoreFile.exists()) {
			return false;

		}
		// Return true if the keystore file exists
		return true;
	}

	/**
	 * Verify if the provided keystore password is correct
	 *
	 * @param keystoreFilePath The path to the keystore file
	 * @param password         The password to verify
	 * @return true if the password is correct, false otherwise
	 */
	private static boolean verifyKeystorePassword(String keystoreFilePath,
			String password) {
		try {
			FileInputStream kfile = new FileInputStream(keystoreFilePath);
			KeyStore kstore = KeyStore.getInstance("PKCS12");
			kstore.load(kfile, password.toCharArray());
			return true; // Password is correct
		} catch (Exception e) {

			if (e.getCause() instanceof UnrecoverableKeyException) {
				return false; // Password is incorrect
			} else {
				e.printStackTrace();
				return false; // Password is incorrect
			}
		}
	}

	// ***********************************************************************************

	// ************ Get the private key and the certificate from the keystore
	// ************
	/**
	 * Retrieves the private key associated with the specified patient user name
	 * from
	 * the keystore file
	 *
	 * @param patientUsername  The user name of the patient whose private key is to
	 *                         be retrieved
	 * @param keystorePassword The password used to access the keystore file
	 * @return The private key associated with the specified user name, or null if
	 *         retrieval fails
	 * @throws Exception If an error occurs during the retrieval process
	 */
	private static PrivateKey getPrivateKey(String patientUsername, String keystorePassword)
			throws Exception {
		try {
			FileInputStream kfile1 = new FileInputStream(
					"cliente/" + patientUsername + "/" + patientUsername + ".keystore");
			KeyStore kstore = KeyStore.getInstance("PKCS12");
			kstore.load(kfile1, keystorePassword.toCharArray());
			return (PrivateKey) kstore.getKey(patientUsername, keystorePassword.toCharArray());
		} catch (UnrecoverableKeyException | IOException | NoSuchAlgorithmException
				| CertificateException e) {
			e.printStackTrace();
		}
		return null; // Return null if private key retrieval fails
	}

	/**
	 * Retrieves the certificate from the keystore file
	 *
	 * @param keystorePath     Path to the keystore file
	 * @param keystorePassword Password for the keystore
	 * @param alias            Alias of the certificate to retrieve
	 * @return Certificate object if found, null otherwise
	 */
	private static Certificate getCertificateFromKeystore(String keystorePath,
			String keystorePassword, String alias) {
		try {
			// Load the keystore file
			FileInputStream kfile = new FileInputStream(keystorePath);
			
			KeyStore kstore = KeyStore.getInstance("PKCS12");
			
			kstore.load(kfile, keystorePassword.toCharArray());
			// Retrieve the certificate using the provided alias
			Certificate cert = kstore.getCertificate(alias);
			return cert;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Checks if the keystore contains a certificate with the specified patient name
	 *
	 * @param keystoreFilePath The file path of the keystore
	 * @param patientName      The patient name to search for in the certificate
	 * @param keystorePassword The password for accessing the keystore
	 * @return true if a certificate with the patient's name is found in the keystore, false otherwise
	 */
	private static boolean containsCertificateWithPatientName(String keystoreFilePath, String patientName, String keystorePassword) {
	    try {
	        File keystoreFile = new File(keystoreFilePath);
	        FileInputStream fis = new FileInputStream(keystoreFile);
	        KeyStore kstore = KeyStore.getInstance("PKCS12");
	        String password = keystorePassword; 
	        kstore.load(fis, password.toCharArray());

	        Enumeration<String> aliases = kstore.aliases();
	        while (aliases.hasMoreElements()) {
	            String alias = aliases.nextElement();
	            Certificate certificate = kstore.getCertificate(alias);
	            if (certificate instanceof X509Certificate) {
	                X509Certificate x509Cert = (X509Certificate) certificate;
	                String subjectDN = x509Cert.getSubjectDN().getName();
	                if (subjectDN.contains(patientName)) {
	                    return true; // Found a certificate with the patient's name
	                }
	            }
	        }
	        
	        fis.close(); 
	        return false; // No certificate with the patient's name found
	    } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
	        e.printStackTrace(); 
	        return false; // Return false if any exception occurs
	    }
	}
	
	// ***********************************************************************************

	/**
	 * Reads a file and writes it on another (only changes the name)
	 * 
	 * @param file              The file
	 * @param signatureFileName The path where the new file will be saved
	 * @throws Exception If an error occurs during the signing process
	 */
	private static void readWrite(File file, String fileName) throws Exception {

		// If the password is correct, proceed to check if the file is already signed
		File existingFile = new File(fileName);
		if (existingFile.exists()) {
			System.out.println("O ficheiro " + file + " já está existe.");
			return; // Exit the method
		}

		try {

			FileInputStream fis;
			FileOutputStream fos;

			fis = new FileInputStream(file);
			fos = new FileOutputStream(fileName);

			byte[] b = new byte[256];
			int i = fis.read(b);

			while (i != -1) {
				fos.write(b, 0, i);
				i = fis.read(b);
			}
			fos.close();
			fis.close();

			System.out.println("O ficheiro foi criado com sucesso: " + fileName);

		} catch (IOException e) {
			e.printStackTrace();

		}
	}

	// ***********************************************************************************

	// ********************** Checks files on the server and client
	// **********************
	/**
	 * Verifies the existence of files on the serve
	 * 
	 * @param filesToSend An array of filenames to be checked on the server
	 * @param out         The ObjectOutputStream for sending data to the server
	 * @param in          The ObjectInputStream for receiving data from the server
	 */
	private static void checkExistenceFilesServer(String[] filesToSend, ObjectOutputStream out,
			ObjectInputStream in) {
		System.out.println("Estabelecendo comunicação com o servidor para verificar os ficheiros.");
		try {
			System.out.println("Em checkExistenceFilesServer");
			out.writeObject(filesToSend);
		} catch (IOException  e) {
			System.out.println("Erro na comunicação com o servidor");
			e.printStackTrace();
		}
	}

	/**
	 * Verifies the existence of specified files on the client's download directory
	 * 
	 * @param encryptedFileName The path to the encrypted file
	 * @param chaveSecreta      The path to the secret key file
	 * @param signedFileName    The path to the signature file
	 * @return true if all specified files exist, false otherwise
	 */
	private static Boolean checkExistenceFilesDownload(String[] filesToSend, String patientUsername) {

		for (String f : filesToSend) {
			// System.out.print("f: " + f.split("\\/")[0] + "/" + f.split("\\/")[1] +
			// "/download/" + f.split("\\/")[3]);
			File file = new File("cliente" + "/" + patientUsername + "/download/" + filesToSend[0]);

			if (!file.exists()) {
				return false;
			} else {
				return true;
			}
		}
		return null;
	}
	
	/**
     * Retrieves the owner of the certificate based on the certificate file and the name to be checked
     *
     * @param certificateFile 	  The certificate file
     * @param nameToCheck 		  The name to be checked
     * @return The name of the certificate owner if it matches the name to be checked; otherwise, null
     */
	public static String getCertificateOwner(String certificateFile, String nameToCheck) {
        try {
            FileInputStream fis = new FileInputStream(certificateFile);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            
            // Parse the certificate file
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            
            // Get the subject DN 
            String subjectDN = cert.getSubjectDN().getName();
            
            String[] dnComponents = subjectDN.split(",");
            for (String component : dnComponents) {
                if (component.startsWith("CN=")) {
                    String commonName = component.substring(3);

                    fis.close();
                    
                    // Check if the common name matches the name to check
                    if (commonName.equals(nameToCheck)) {
                        return commonName;
                    } else {
                        return null; // Return null if the names don't match
                    }
                }
            }
            
            fis.close();
            
        } catch (FileNotFoundException fnfe) {
            System.err.println("Ficheiro não encontrado no cliente: " + "' " + certificateFile + "' " + ".");
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null; // Return null if owner cannot be determined
    }
	
	/**
	 * Adds a certificate to the keystore
	 *
	 * @param alias 	       The alias under which the certificate should be stored in the keystore
	 * @param keystorePath 	   The path to the keystore file
	 * @param keystorePassword The password for the keystore
	 * @param in 			   The ObjectInputStream used to receive the certificate or error message from the server
	 * @param out 			   The ObjectOutputStream used to send any response back to the server
	 * @return true if the certificate is added successfully, false otherwise
	 */
	public static boolean addCertificate(String alias, String keystorePath, String keystorePassword, ObjectInputStream in, ObjectOutputStream out) {
        try {
            FileInputStream kfile = new FileInputStream(keystorePath);
            KeyStore kstore = KeyStore.getInstance("PKCS12");
            kstore.load(kfile, keystorePassword.toCharArray());

            // Receive the certificate or error message from the server
            Object object = in.readObject();
            if (object instanceof Certificate) {
                // Certificate received, proceed with adding it to the keystore
                Certificate certificate = (Certificate) object;
                
                kstore.setCertificateEntry(alias, certificate);
                // Save the keystore back to the file
                FileOutputStream fos = new FileOutputStream(keystorePath);
                kstore.store(fos, keystorePassword.toCharArray());
                fos.close();
                return true; 
            } else if (object instanceof String) {
                // Error message received from the server
                String errorMessage = (String) object;
                System.err.println("Erro do servidor: "+errorMessage);
                // Exit the method
                return false;
            } else {
                System.err.println("Unexpected object received from server");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false; 
        }
    }
}
