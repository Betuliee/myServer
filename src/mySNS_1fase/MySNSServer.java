package mySNS_1fase;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.lang.invoke.StringConcatFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

public class MySNSServer extends Thread {

	private static final int REGULAR_PORT = 23456;
	private static final String SERVER_DIRECTORY = "servidor/";
	private static final String USERS_FILE_PATH = "servidor/users.txt";
	private static final String MAC_FILE_PATH = "servidor/mac.txt";
	private static final String CERT_FILE = "cert";
	private static final String HASH_ALGORITHM = "SHA-256";
	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private static String errorMessage = "";
	private static String successMessage = "";

	public static void main(String[] args) throws Exception {

		System.setProperty("javax.net.ssl.keyStore", "keystore.server");
		System.setProperty("javax.net.ssl.keyStorePassword", "123456");

		System.out.println("Servidor: main");
		MySNSServer server = new MySNSServer();
		server.startServer();
	}

	public void startServer() throws Exception {

		// Check if the password file exists
		File usersFile = new File(USERS_FILE_PATH);
		if (!usersFile.exists()) {
			// If it doesn't exist, create the file with admin user
			try {
				System.out.println("Ficheiro " + usersFile + " não existe. Criando o ficheiro...");
				criarFileUsers(usersFile);
			} catch (Exception e) {
				System.err.println("Erro na criação do ficheiro: " + e.getMessage());
				e.printStackTrace();
				System.exit(-1);
			}
		} else {
			System.out.println("O ficheiro " + usersFile + " já existe.");
		}

		// Check if there's MAC protecting the file
		if (!isMacExists()) {
			// If there's no MAC, ask the admin if they want to calculate MAC
			System.err.println("Aviso: Não há MAC a proteger o ficheiro.");
			Scanner scanner = new Scanner(System.in);
			System.out.print("Pretende calcular o MAC para o ficheiro? (sim/nao): ");
			String response = scanner.nextLine();
			if (response.equalsIgnoreCase("sim")) {
				calculateAndWriteMAC(response);
			} else {
				System.out.println("AVISO: O ficheiro não está protegido por MAC. Terminando o programa.");
				System.exit(-1);
			}

		}

		// Ask for admin for password
		Scanner scanner = new Scanner(System.in);
		System.out.print("Insira a password de admin para o ficheiro 'users.txt': ");
		String adminPassword = scanner.nextLine();

		// Calculate MAC for password file
		byte[] macBytes = calculateAndWriteMAC(adminPassword);

		// Check integrity of password file
		if (!checkPasswordFileIntegrity(macBytes)) {
			System.err.println("Erro: Verificação de integridade do ficheiro de passwords falhou! Terminando o programa...");
			System.exit(-1);
		} else {
			System.out.println("Verificação de integridade do ficheiro de passwords aprovada.");
		}

		ServerSocket sSoc = null;

		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault(); // Socket SSL
			sSoc = ssf.createServerSocket(REGULAR_PORT);
			System.out.println("Servidor iniciado. Aguardando conexões...");
		} catch (IOException e) {
			System.err.println("Erro ao iniciar o servidor: " + e.getMessage());
			System.exit(-1);
		}

		while (true) {
			try {
				Socket inSoc = sSoc.accept();
				System.out.println("Cliente conectado: " + inSoc.getInetAddress());
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		// sSoc.close();
	}

	/*********************************************
	 * TRABALHO 2
	 *********************************************/

	/**
	 * Creates a file containing user information, including an admin user
	 *
	 * @param usersFile The file to be created
	 * @throws Exception If an error occurs while creating the file
	 */
	private void criarFileUsers(File usersFile) throws Exception {
		try (PrintWriter writer = new PrintWriter(usersFile)) {
			// Create the file with admin user
			String adminUsername = "admin";
			Scanner scanner = new Scanner(System.in);
			System.out.print("Insira a password de admin para o ficheiro 'users.txt': ");
			String adminPassword = scanner.nextLine();
			if (adminPassword != null && !adminPassword.isEmpty()) {
				String adminUserLine = createUserWithRandomSalt(adminUsername, adminPassword);
				writer.println(adminUserLine);
				System.out.println("Ficheiro de users criado com o user admin e a respetiva password.");
			} else {
				System.err.println("Password cannot be null or empty.");
				System.exit(-1);
			}

		} catch (Exception e) {
			System.err.println("Erro na criação do ficheiro: " + e.getMessage());
			e.printStackTrace();
			System.exit(-1);
		}
	}

	/**
	 * Calculates and writes the MAC for the admin password
	 *
	 * @param adminPassword The admin password to calculate the MAC for
	 * @return The calculated MAC bytes
	 * @throws Exception If an error occurs while calculating the MAC
	 */
	private byte[] calculateAndWriteMAC(String adminPassword) throws Exception {

		// Create the file if it doesn't exist
		File macFile1 = new File(MAC_FILE_PATH);
		if (!macFile1.exists()) {
			macFile1.createNewFile();
		}
		// Initialize the secret key
		SecretKeySpec secretKey = new SecretKeySpec(adminPassword.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
		// Initialize the MAC instance
		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(secretKey);
		// Read the file and update the MAC
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(MAC_FILE_PATH);
			byte[] buffer = new byte[2048];
			int bytesRead;
			while ((bytesRead = fis.read(buffer)) != -1) {
				mac.update(buffer, 0, bytesRead);
			}
		} finally {
			if (fis != null) {
				fis.close();
			}
		}

		// Calculate the MAC
		byte[] macBytes = mac.doFinal();

		// Write the MAC to a file
		try (FileOutputStream macFile = new FileOutputStream(MAC_FILE_PATH)) {
			macFile.write(macBytes);
			macFile.close();
		}

		// Return the MAC
		return mac.doFinal(getFileBytes(USERS_FILE_PATH));
	}

	/**
	 * Checks the integrity of the password file by comparing the expected MAC
	 * with the calculated MAC.
	 *
	 * @param expectedMAC The expected MAC bytes to compare with the calculated MAC
	 * @return true if the password file integrity is verified, false otherwise
	 */
	private boolean checkPasswordFileIntegrity(byte[] expectedMAC) throws Exception {
		String adminPassword = promptAdminPassword();
		byte[] calculatedMAC = calculateAndWriteMAC(adminPassword);
		return MessageDigest.isEqual(expectedMAC, calculatedMAC);
	}

	private byte[] getFileBytes(String filePath) throws IOException {
		File file = new File(filePath);
		try (FileInputStream fis = new FileInputStream(file)) {
			byte[] bytes = new byte[(int) file.length()];
			fis.read(bytes);
			return bytes;
		}
	}

	/**
	 * Prompts the admin for the password to verify the integrity of the password
	 * file
	 *
	 * @return The password entered by the admin
	 */
	private String promptAdminPassword() {
		Scanner scanner = new Scanner(System.in);
		System.out.print("Insira a password do admin para verificar a integridade do ficheiro de passwords: ");
		return scanner.nextLine();
	}

	/**
	 * Checks if the MAC file exists
	 *
	 * @return true if the MAC file exists, false otherwise
	 */
	private boolean isMacExists() {
		File macFile = new File(MAC_FILE_PATH);
		return macFile.exists();
	}

	/**
	 * Creates a user entry with a random salt and hashed password
	 *
	 * @param username The username of the user
	 * @param password The password of the user
	 * @return The user entry with username, salt, and hashed password, separated by
	 *         semicolons
	 */
	private String createUserWithRandomSalt(String username, String password) throws Exception {
		byte[] salt = generateRandomSalt();
		String hashedPassword = hashPasswordWithSalt(password, salt);
		String saltBase64 = Base64.getEncoder().encodeToString(salt);
		String hashedPasswordBase64 = Base64.getEncoder().encodeToString(hashedPassword.getBytes());
		return username + ";" + saltBase64 + ";" + hashedPasswordBase64;
	}

	/**
	 * Generates a random salt
	 *
	 * @return A byte array containing the random salt
	 */
	private byte[] generateRandomSalt() throws Exception {
		SecureRandom secureRandom = new SecureRandom();
		byte[] salt = new byte[16];
		secureRandom.nextBytes(salt);
		return salt;
	}

	/**
	 * Hashes the password with the provided salt using a specified hashing algorith
	 *
	 * @param password The password to be hashed
	 * @param salt     The salt used in the hashing process
	 * @return A hashed password string
	 * @throws Exception If an error occurs while hashing the password
	 */
	private static String hashPasswordWithSalt(String password, byte[] salt) throws Exception {
		MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
		digest.reset();
		digest.update(salt);
		byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(hash);
	}

	/*********************************************
	 * TRABALHO 2
	 *********************************************/

	// Threads for communication with clients
	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("thread do server para cada cliente");
		}

		public void run() {
			try {
				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

				String doctorUsername = null;
				String patientUsername = null;
				String[] filenames = null;

				/* trab 2 */
				String username = null;
				String password = null;
				/* trab 2 */

				// Read the objects
				doctorUsername = (String) inStream.readObject();
				patientUsername = (String) inStream.readObject();
				filenames = (String[]) inStream.readObject();
				/* trab 2 */
				username = (String) inStream.readObject();
				password = (String) inStream.readObject();
				/* trab 2 */
				
				System.out.println("Filenames recebidos: " + Arrays.toString(filenames));

				/*********************************************
				 * TRABALHO 2
				 *********************************************/
				String message = "";
				if (username != null) {
					if (usernameExists(username)) {
						// Username already exists
						String errorMessage = "Erro: Username '" + username + "' já existe. Terminando o programa.";
						outStream.writeObject(errorMessage);
						outStream.flush();
						System.err.println(errorMessage);
						System.exit(-1);
					} else {
						message = "Novo utilizador: '" + username + "'.";
						outStream.writeObject(message);
						outStream.flush();
						System.out.println(message);
					
						try {
							Object response = inStream.readObject();

							// Handle the client response
							if (response instanceof String) {
								message = (String) response;
								if (message.startsWith("Erro")) {
									// Error message from the server
									System.err.println("Erro do cliente: " + message);
									System.exit(-1);
								} else {
									System.out.println("Mensagem de sucesso do cliente: " + message);
								}
							} else {
								System.err.println("Resposta inesperada do servidor");
							}
							
							String novoUser = createUserWithRandomSalt(username, password);
							saveUserToFile(novoUser);

							// System.out.println("users existentes: "+ createdUsers);
							successMessage = "Username '" + username + "' criado com sucesso.";
							outStream.writeObject(successMessage);
							outStream.flush();
							System.out.println(successMessage);
							
							// Criar diretório do novo user, se ainda não existir
							createDirectoryForUser(username);
							
							// Create directory for the new user if it doesn't already exist
							createDirectoryForUser(username);

							receiveCertificateFromClient(CERT_FILE, inStream);
							System.exit(1);
						} catch (Exception e) {
							System.err.println("Erro na receção dos ficheiros no servidor");
							e.printStackTrace();
						}

					}
				}

				// Check if the provided usernames exist in the set of created users
				boolean doctorExists = usernameExists(doctorUsername);
				boolean patientExists = usernameExists(patientUsername);

				/*********************************************
				 * TRABALHO 2
				 *********************************************/

				if (doctorUsername != null) {

					if (doctorExists && patientExists) {

						// Construct the success message for doctor and patient existence
						String successMessage = "O nome do médico e do utente existem no ficheiro: " + USERS_FILE_PATH;

						// Check if doctor authentication is successful
						boolean isAuthenticated = checkPassword(doctorUsername, password);

						// Construct the success message for authentication
						String successMessage2 = "";
						if (isAuthenticated) {
							successMessage2 = "Autenticação bem-sucedida. A Prosseguir...";
						} else {
							errorMessage = "Erro: A autenticação falhou devido à password incorreta. Terminando o programa.";
							outStream.writeObject(errorMessage);
							outStream.flush();
							System.err.println(errorMessage);
							System.exit(-1);
						}

						// Combine both success messages with a delimiter
						String combinedSuccessMessage = successMessage + " ||| " + successMessage2;
						
						// Send the combined success message
						outStream.writeObject(combinedSuccessMessage);
						outStream.flush();
						System.out.println(combinedSuccessMessage);
						
						
						/*********************************************
						 * CERTIFICADO
						 *********************************************/

						loadAndSendCertificate(outStream, patientUsername);
		                
						/*********************************************
						 * CERTIFICADO
						 *********************************************/

						try {

							Object response = inStream.readObject();

							// Handle the client response
							if (response instanceof String) {
								message = (String) response;
								if (message.startsWith("Erro")) {
									// Error message from the server
									System.err.println("Erro do cliente: " + message);
									System.exit(-1);
								} else {
									System.out.println("Mensagem de sucesso do cliente: " + message);
								}
							} else {
								System.err.println("Resposta inesperada do servidor");
							}

							receiveFilesFromClient(patientUsername, inStream);

						} catch (Exception e) {
							System.err.println("Erro na receção dos ficheiros no servidor");
							e.printStackTrace();
						}
					} else if (!doctorExists && !patientExists) {
						String errorMessage = "Erro: O nome do médico e do utente ainda não existem no ficheiro: "
								+ USERS_FILE_PATH;
						outStream.writeObject(errorMessage);
						outStream.flush();
						System.err.println(errorMessage);
					}
					// Check which name doesn't exist
					else if (!doctorExists) {
						errorMessage = "Erro: O nome do médico '" + doctorUsername + "' não existe no ficheiro:"
								+ USERS_FILE_PATH + ". Terminando o programa.";
						outStream.writeObject(errorMessage);
						outStream.flush();
						System.err.println(errorMessage);
						System.exit(-1);
					} else if (!patientExists) {
						errorMessage = "Erro: O nome do utente '" + patientUsername + "' não existe no ficheiro:"
								+ USERS_FILE_PATH + ". Terminando o programa.";
						outStream.writeObject(errorMessage);
						outStream.flush();
						System.err.println(errorMessage);
						System.exit(-1);

					}

				} else if (patientExists) {

					String successMessage = "O nome do utente existe no ficheiro: " + USERS_FILE_PATH;
					// Check if doctor authentication is successful
					boolean isAuthenticated = checkPassword(patientUsername, password);

					// Construct the success message for authentication
					String successMessage2 = "";
					if (isAuthenticated) {
						successMessage2 = "Autenticação bem-sucedida. A Prosseguir...";
					} else {
						errorMessage = "Erro: Autenticação falhou. Terminando o programa.";
						outStream.writeObject(errorMessage);
						outStream.flush();
						System.err.println(errorMessage);
						System.exit(-1);
					}

					// Combine both success messages with a delimiter
					String combinedSuccessMessage = successMessage + " ||| " + successMessage2;

					// Send the combined success message
					outStream.writeObject(combinedSuccessMessage);
					outStream.flush();
					System.out.println(combinedSuccessMessage);
					
					String medico = getMedicoFromFilenames(filenames, patientUsername);
					outStream.writeObject(medico);
					outStream.flush();
					
					/*********************************************
					 * CERTIFICADO
					 *********************************************/

					boolean certificateNeeded = (boolean) inStream.readObject();

					if (certificateNeeded) {
					   loadAndSendCertificate(outStream, medico);
					}
	                
					/*********************************************
					 * CERTIFICADO
					 *********************************************/


					try {

						Object response = inStream.readObject();

						// Handle the client response
						if (response instanceof String) {
							message = (String) response;
							if (message.startsWith("Erro")) {
								// Error message from the server
								System.err.println("Erro do cliente: " + message);
								System.exit(-1);
							} else {
								System.out.println("Mensagem de sucesso do cliente: " + message);
							}
						} else {
							System.err.println("Resposta inesperada do servidor");
						}

					} catch (Exception e) {
						System.err.println("Erro na receção dos ficheiros no servidor");
						e.printStackTrace();
					}

					for (String f : filenames) {
						
					
						System.out.println("Ficheiro:" + f);
						try {
							verificarExistenciaFicheiros(patientUsername, inStream, outStream);
						} catch (Exception e) {
							e.printStackTrace();
						}
					}

				} else {
					errorMessage = "Erro: O nome do utente '" + patientUsername + "' não existe no ficheiro:"
							+ USERS_FILE_PATH + ". Terminando o programa.";
					outStream.writeObject(errorMessage);
					outStream.flush();
					System.err.println(errorMessage);
					System.exit(-1);

				}

				// Close streams
				outStream.close();
				inStream.close();
				socket.close();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	private String getMedicoFromFilenames(String[] filenames, String patientUsername) {
	    for (String f : filenames) {
	        String directoryPath =  "servidor/" + patientUsername;

	        // Get doctor username
	        // The desired file extension to get the doctor user name
	        String desiredExtension = f + ".assinatura";
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
	        return medico;
	    }
	    return null; // Se nenhum médico for encontrado
	}


	/*********************************************
	 * TRABALHO 2
	 *********************************************/
	/**
	 * Checks if a username exists in the user file
	 *
	 * @param username The username to check for existence
	 * @return true if the username exists, false otherwise
	 */
	private boolean usernameExists(String username) {
		boolean found = false; // Flag to track if the username is found
		try (BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE_PATH))) {
			String line;
			// Read each line in the file
			while ((line = reader.readLine()) != null) {
				String[] parts = line.split(";");
				if (parts.length > 0 && parts[0].equals(username)) {
					found = true; // Username found
					break; // break the loop if the username is found
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return found;
	}

	/**
	 * Checks if the provided password matches the stored password for the given
	 * username
	 *
	 * @param username The username to check
	 * @param password The password to authenticate
	 * @return true if the password is correct, false otherwise
	 * @throws Exception If an error occurs during the password checking process
	 */
	public static boolean checkPassword(String username, String password) throws Exception {
		boolean userFound = false;
		try (BufferedReader br = new BufferedReader(new FileReader(USERS_FILE_PATH))) {
			String line;
			while ((line = br.readLine()) != null) {
				String[] parts = line.split(";");
				if (parts.length == 3) {
					String storedUsername = parts[0];
					String storedSaltBase64 = parts[1];
					String storedHashedPassword = parts[2];

					if (storedUsername.equals(username)) {
						byte[] storedSalt = Base64.getDecoder().decode(storedSaltBase64);
						String hashedPasswordToCheck = hashPasswordWithSalt(password, storedSalt);
						byte[] storedHashedPasswordBytes = Base64.getDecoder().decode(storedHashedPassword);

						if (MessageDigest.isEqual(storedHashedPasswordBytes,
								hashedPasswordToCheck.getBytes(StandardCharsets.UTF_8))) {
							userFound = true;
							break; // Exit the loop when user is found
						}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (!userFound) {
			// System.out.println("Erro: Autenticação falhou. Terminando o programa.");
		}
		return userFound;
	}

	/*********************************************
	 * TRABALHO 2
	 *********************************************/

	// private void processClientRequest(BufferedReader br, PrintWriter pw, Socket
	// socket) throws IOException {
	//
	// String data = br.readLine();
	// pw.println("What is she?");
	// pw.close();
	// socket.close();
	// }

	/**
	 * Verifies the existence of files
	 *
	 * @param patientUsername The username of the patient whose files are being
	 *                        verified
	 * @param inStream        The input stream to receive filenames from the client
	 * @param outStream       The output stream to send messages or files to the
	 *                        client
	 * @throws IOException If an I/O error occurs while reading from the stream
	 */
	private void verificarExistenciaFicheiros(String patientUsername, ObjectInputStream inStream,
			ObjectOutputStream outStream)
			throws Exception {
		try {
			System.out.println("No verificarExistenciaFicheiros");
			// Attempt to receive the filename from the client
			String[] fileToGet = (String[]) inStream.readObject();

			System.out.println("Filename recebido: " + Arrays.toString(fileToGet));
			String[] filenames = buscarFicheiros(fileToGet[0], patientUsername);

			if (Arrays.toString(filenames) == "[]") {
				System.out.println("Não existem ficheiros.");
				// System.exit(1);
				// Notify the client that there are no corresponding files and move on
				outStream.writeObject(false); // o boolean é recebido na receiveFilesFromServer
			} else {
				// Notifies the client that there are corresponding files; the client proceeds
				// to receive them
				outStream.writeObject(true); // The boolean is received in the receiveFilesFromServer function
			}

			for (String filename : filenames) {
				System.out.println("Filename em verificarExistenciaFicheiros " + filename);
				
				if (!filename.equals("No files")) {

					System.out.println("Verificando o ficheiro: " + filename);

					String filePath = SERVER_DIRECTORY + patientUsername + "/" + filename;

					System.out.println("Caminho do ficheiro " + filePath);

					String fileString = filePath.split("/")[2];
					// Check if the file already exists
					File file = new File(filePath);

					if (!file.exists()) {
						String msg = "O ficheiro " + fileString + " não existe no servidor";
						System.out.println(msg);
					}
					// if file exists
					else {
						String msg = "O ficheiro " + filename + " existe: Enviando ...";
						System.out.println(msg);
						// outStream.writeObject(msg);
						sendFilesToClient(file, outStream);
					}

				} else {
					System.out.println("Não há ficheiros para receber do cliente");
				}
			}
			
			String msg = "Verificação concluída";
			System.out.println(msg);
			
//			if (Arrays.toString(filenames) != "[]") {
//				String message = "";
//				Object response = inStream.readObject();
//	
//				// Handle the client response
//				if (response instanceof String) {
//					message = (String) response;
//					if (message.startsWith("Erro")) {
//						// Error message from the server
//						System.err.println("Erro do cliente: " + message);
//						System.exit(-1);
//					} else {
//						System.out.println("Nome do médico a receber pelo cliente: " + message);
//						String medico = (String) message;
//						loadAndSendCertificate(outStream, medico);
//					}
//				} else {
//					System.err.println("Resposta inesperada do servidor");
//				}
//			}

		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		}
	}

	private String[] buscarFicheiros(String string, String patientUsername) {
		List<String> nomesFicheiros = new ArrayList<String>();
		File dir = new File("servidor/" + patientUsername);
		// busca todos ficheiros do diretorio com o nome do ficheiro desejado
		File[] todosFicheiros = dir.listFiles(new FilenameFilter() {
			public boolean accept(File dir, String fname) {
				return fname.startsWith(string);
			}
		});
		// obtem o nome dos ficheiros
		for (File f : todosFicheiros) {
			nomesFicheiros.add(f.getName());
		}
		// passa para array
		String[] ficheiros = nomesFicheiros.toArray(new String[0]);
		return ficheiros;

	}

	/**
	 * Receives files from the client for the specified patient user name
	 *
	 * @param patientUsername The user name of the patient
	 * @param inStream        The ObjectInputStream used to receive data from the
	 *                        client
	 * @throws Exception If an error occurs while receiving files from the client
	 */
	private void receiveFilesFromClient(String patientUsername, ObjectInputStream inStream) throws Exception {
		try {
			while (true) {
				try {
					System.out.println("No receiveFilesFromClient");
					// Attempt to receive the filename from the client
					String filename = (String) inStream.readObject();

					// If no exception is thrown, proceed to receive file data
					long fileSize = inStream.readLong();

					System.out.println("Recebendo o ficheiro: " + filename);

					System.out.println("Dimensão do ficheiro: " + fileSize);

					// Extracting filename
					String file = SERVER_DIRECTORY + patientUsername + "/" + filename.split("/")[3];

					// Check if the file already exists
					File existingFile = new File(file);
					if (existingFile.exists()) {
						System.out.println("O ficheiro '" + filename + "'  já existe no servidor. Será omitido...");
						// Consume the incoming data from the stream to discard it
						long bytesSkipped = 0;
						while (bytesSkipped < fileSize) {
							long remainingBytes = fileSize - bytesSkipped;
							int bytesToSkip = (int) Math.min(2048, remainingBytes);
							bytesSkipped += inStream.skip(bytesToSkip);
						}
						continue; // Skip to the next file
					}

					FileOutputStream fos = new FileOutputStream(file);
					BufferedOutputStream bos = new BufferedOutputStream(fos);

					byte[] buffer = new byte[2048];
					int bytesRead;
					while (fileSize > 0
							&& (bytesRead = inStream.read(buffer, 0,
									(int) Math.min(buffer.length, fileSize))) != -1) {
						bos.write(buffer, 0, bytesRead);
						fileSize -= bytesRead;
					}

					bos.close();
					fos.close();

					System.out.println("Ficheiros recebidos no servidor");
				} catch (EOFException e) {
					// No more files to receive, break out of the loop
	                System.out.println("No more files to receive from the client.");
					break;
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * 
	 * Send files to the client
	 * 
	 * @param file      The file to be sent
	 * @param outStream The ObjectOutputStream used to send data to the client
	 * @throws IOException If an I/O error occurs while sending the file
	 */
	private void sendFilesToClient(File file, ObjectOutputStream outStream) throws IOException {
		FileInputStream fis = null;
		try {

			// Open the file
			fis = new FileInputStream(file);

			// Send the file name to the client
			outStream.writeObject(file.getName());
			System.out.println(file.getName());

			// Send the file size to the client
			outStream.writeLong(file.length());

			// Create a buffer for reading the file
			byte[] buffer = new byte[2048];
			int bytesRead;
			// Read and send file data in chunks
			while ((bytesRead = fis.read(buffer)) != -1) {
				outStream.write(buffer, 0, bytesRead);
			}
			// Flush the ObjectOutputStream to ensure all data is sent
			outStream.flush();
			System.out.println("Ficheiro enviado para o cliente: " + file.getName());
		} finally {
			// Close the FileInputStream
			if (fis != null) {
				fis.close();
			}
		}
	}

	/*********************************************
	 * TRABALHO 2
	 *********************************************/

	/**
	 * Creates a directory for the specified user
	 *
	 * @param username The username for which the directory is to be created
	 * @throws IOException If an I/O error occurs while creating the directory
	 */
	private void createDirectoryForUser(String username) throws IOException {
		Path newUserDirectory = Paths.get(SERVER_DIRECTORY, username);
		if (!Files.exists(newUserDirectory)) {
			Files.createDirectories(newUserDirectory);
			System.out.println("Diretório do utilizador criado: " + newUserDirectory);
		}
	}

	/**
	 * Receives a certificate file from the client for the specified user
	 *
	 * @param patientUsername The username of the patient
	 * @param inStream        The input stream to receive data from the client
	 * @throws Exception If an error occurs while receiving the certificate file
	 */
	private void receiveCertificateFromClient(String cert, ObjectInputStream inStream) throws Exception {
		try {
			while (true) {
				try {
					System.out.println("No receiveCertificateFromClient");
					// Attempt to receive the filename from the client
					String filename = (String) inStream.readObject();

					// If no exception is thrown, proceed to receive file data
					long fileSize = inStream.readLong();

					System.out.println("Recebendo o ficheiro: " + filename);

					System.out.println("Dimensão do ficheiro: " + fileSize);

					// Extracting filename
					String file = SERVER_DIRECTORY + cert + "/" + filename;

					// Check if the file already exists
					File existingFile = new File(file);
					if (existingFile.exists()) {
						System.out.println("O ficheiro '" + file + "'  já existe no servidor. Será omitido...");
						long bytesSkipped = 0;
						while (bytesSkipped < fileSize) {
							long remainingBytes = fileSize - bytesSkipped;
							int bytesToSkip = (int) Math.min(2048, remainingBytes);
							bytesSkipped += inStream.skip(bytesToSkip);
						}
						continue; // Skip to the next file
					}

					FileOutputStream fos = new FileOutputStream(file);
					BufferedOutputStream bos = new BufferedOutputStream(fos);

					byte[] buffer = new byte[2048];
					int bytesRead;
					while (fileSize > 0
							&& (bytesRead = inStream.read(buffer, 0,
									(int) Math.min(buffer.length, fileSize))) != -1) {
						bos.write(buffer, 0, bytesRead);
						fileSize -= bytesRead;
					}

					bos.close();
					fos.close();

					System.out.println("Ficheiros recebidos no servidor");
				} catch (EOFException e) {
					// No more files to receive, break out of the loop
					break;
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			throw e;
		}
	}

	/**
	 * Saves the user information to the specified file
	 *
	 * @param user The user information to be saved
	 * @throws IOException If an I/O error occurs while saving the user information
	 */
	private static void saveUserToFile(String user) throws IOException {
		try (FileWriter fw = new FileWriter(USERS_FILE_PATH, true);
				BufferedWriter bw = new BufferedWriter(fw);
				PrintWriter out = new PrintWriter(bw)) {
			out.println(user);
		}
	}
	
	public static void loadAndSendCertificate(ObjectOutputStream outStream, String patientUsername) throws IOException {
        // Load the certificate file
        String filePath = "servidor/cert/" + patientUsername + ".cert";
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            FileInputStream fileInputStream = new FileInputStream(filePath);
            Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
            fileInputStream.close();

            // Send the certificate to the client
            outStream.writeObject(certificate);
        } catch (java.io.FileNotFoundException e) {
            // File not found, send error message to the client
            String errorMessage = "Erro: Ficheiro do certificado não encontrado para " + patientUsername + ".";
            System.err.println(errorMessage);
            try {
                outStream.writeObject(errorMessage);
            } catch (Exception ex) {
                ex.printStackTrace(); 
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
	/*********************************************
	 * TRABALHO 2
	 *********************************************/
}
