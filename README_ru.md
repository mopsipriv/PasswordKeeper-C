# **🔐 Password Keeper**

## **Project Description**

**Password Keeper** is an early prototype of a password manager, written in C/C++ using Qt for a potential graphical user interface (GUI) and CMake for the build system.  
The primary goals of the project are:

* Storing confidential data (websites, logins, and passwords).  
* Demonstrating basic principles of cryptography and secure data handling.

## **🛠️ Technologies Used and Current Functionality**

| Aspect | Technology / Status | Comment |
| :---- | :---- | :---- |
| **Language / Build** | C/C++ / CMake | The project uses a modern build approach via CMake. |
| **Graphical Interface** | Qt | Used for cross-platform GUI development (the GUI may not be fully implemented in the current version). |
| **Master Key Hashing** | SHA-256 | A strong hashing algorithm is used to protect the main password (Master Key). |
| **Data Encryption** | XOR Encryption | Data is stored in the file using simple XOR encryption. |

## **🚧 Plans and Roadmap**

The project is in its early stages. The main priority is enhancing security and improving the user experience.

### **Security**

* **Encryption Strengthening:** The current XOR encryption with a fixed key is too weak. The plan is to transition to a modern and robust algorithm (e.g., AES) to provide real data protection.  
* **Salt and Iterations:** Add the use of salt and increase the number of iterations (Key Stretching) when hashing the Master Key to protect against rainbow tables and brute-force attacks.

### **Features**

* **Website Search:** Add a function for quick and convenient searching of entries by website name.  
* **Improved I/O Handling:** Add the ability to export and import data.

### **Stack / GUI Change**

* **Transition to Python GUI:** The possibility of redesigning the interface using Python (e.g., Qt for Python / PySide or Tkinter) for faster GUI development is planned for the future.

*This project is an educational prototype. It is recommended not to use it for storing critically important passwords until more robust cryptographic systems are implemented.*