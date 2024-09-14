import argparse
import logging
from password_manager import PasswordManager
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def main():
    # Initialize the argument parser
    parser = argparse.ArgumentParser(description="Password Manager")

    # Add arguments
    parser.add_argument("action", choices=["add", "get", "delete", "list", "change"],
                        help="Action to perform: add, get, delete, list, change")
    parser.add_argument("--service", help="Service name (required for add, get, delete, change actions)")
    parser.add_argument("--username", help="Username for the service (required for add action)")
    parser.add_argument("--password", help="Password for the service (required for add and change actions)")
    parser.add_argument("--new_password", help="New password for the service (required for change action)")

    # Parse the arguments
    args = parser.parse_args()

    # Initialize the password manager
    password_manager = PasswordManager()
    master_password = password_manager.get_master_password()
    password_manager.set_master_password(master_password)

    # Perform actions based on the arguments
    if args.action == "add":
        if not args.service or not args.username or not args.password:
            logging.error(Fore.RED + "Service, username, and password are required for adding a password.")
        else:
            password_manager.add_password(args.service, args.username, args.password)
            print(Fore.GREEN + f"Password added for service: {args.service}")

    elif args.action == "get":
        if not args.service:
            logging.error(Fore.RED + "Service is required for retrieving a password.")
        else:
            try:
                username, password = password_manager.get_password(args.service)
                print(Fore.GREEN + f"Service: {args.service}, Username: {username}, Password: {password}")
            except ValueError as e:
                logging.error(Fore.RED + str(e))

    elif args.action == "delete":
        if not args.service:
            logging.error(Fore.RED + "Service is required for deleting a password.")
        else:
            password_manager.delete_password(args.service)
            print(Fore.GREEN + f"Password deleted for service: {args.service}")

    elif args.action == "list":
        passwords = password_manager.list_passwords()
        for entry in passwords:
            print(Fore.GREEN + str(entry))

    elif args.action == "change":
        if not args.service or not args.new_password:
            logging.error(Fore.RED + "Service and new password are required for changing a password.")
        else:
            password_manager.change_password(args.service, args.new_password)
            print(Fore.GREEN + f"Password changed for service: {args.service}")

if __name__ == "__main__":
    main()