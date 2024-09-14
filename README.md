# Password Manager


This project is a secure and efficient password manager written in Python. It allows users to store, retrieve, delete, list, and change passwords for various services. The passwords are securely encrypted and stored in a SQLite database, and the application supports multi-factor authentication (MFA) for enhanced security.

## Features

- **Add Password**: Store a new password for a service.
- **Get Password**: Retrieve the stored password for a service.
- **Delete Password**: Remove the stored password for a service.
- **List Passwords**: List all stored passwords.
- **Change Password**: Update the stored password for a service.
- **Multi-Factor Authentication (MFA)**: Adds an extra layer of security.

## Installation

### Prerequisites

- Python 3.6 or higher
- `pip` (Python package installer)

### Steps

1. Clone the repository:
    ```bash
    git clone https://github.com/semihsinansimsek57/password-manager.git
    cd password-manager
    ```

2. Create a virtual environment and activate it:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Run the application:
    ```bash
    python project.py --usage
    ```

5. (Optional) Use the packaged version for Linux:
    ```bash
    ./password-manager --usage
    ```

## Usage

### Command Line Interface

The password manager can be used via the command line. Below are the available commands:

- **Add a password**:
    ```bash
    python project.py add --service <service_name> --username <username> --password <password>
    ```

- **Get a password**:
    ```bash
    python project.py get --service <service_name>
    ```

- **Delete a password**:
    ```bash
    python project.py delete --service <service_name>
    ```

- **List all passwords**:
    ```bash
    python project.py list
    ```

- **Change a password**:
    ```bash
    python project.py change --service <service_name> --new_password <new_password>
    ```

### Example

To add a password for a service:
```bash
python project.py add --service example --username user --password pass1234
```

To retrieve the password for a service:
```bash
python project.py get --service example
```

## Security

- **Encryption**: Passwords are encrypted using the master password and stored securely in a SQLite database.
- **Multi-Factor Authentication (MFA)**: MFA is required to access the password manager, providing an additional layer of security.
- **Secure Storage**: Sensitive data such as the master password and MFA secret are securely stored and permissions are set to restrict access.

## Running Security Audits

To run security audits on the codebase, use the provided `audit_security.sh` script:
```bash
./audit_security.sh
```

This script will:
- Run `bandit` to check for security issues in the Python code.
- Run `safety` to check for known vulnerabilities in dependencies.
- Ensure the `secure` library is up-to-date.

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## License


## Acknowledgements

- [Colorama](https://pypi.org/project/colorama/)
- [PyOTP](https://pypi.org/project/pyotp/)
- [PyQRCode](https://pypi.org/project/PyQRCode/)
- [bcrypt](https://pypi.org/project/bcrypt/)
- [cryptography](https://pypi.org/project/cryptography/)
- [pysqlcipher3](https://pypi.org/project/pysqlcipher3/)

## Contact

