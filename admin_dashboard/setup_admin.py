"""Create an administrator without saving plaintext credentials."""
import argparse
import getpass
import secrets
from .config import Config
from .services.auth_service import AuthService
from waf.management.store import ManagementStore

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--username",default="admin")
    parser.add_argument('--role',choices=['ADMIN','VIEWER'],default='ADMIN')
    parser.add_argument("--generate",action="store_true",help="Print a one-time generated password")
    args=parser.parse_args()
    service=AuthService(ManagementStore(Config.DATABASE_URL or Config.DATABASE_PATH))
    if service.exists(args.username):
        parser.error("That administrator already exists; choose another username.")
    password=secrets.token_urlsafe(18) if args.generate else getpass.getpass("Password (minimum 12 characters): ")
    if not args.generate and password!=getpass.getpass("Confirm password: "):
        parser.error("Passwords differ")
    service.provision(args.username,password,args.role)
    print("Administrator created:",args.username)
    if args.generate:
        print("One-time password:",password)

if __name__=="__main__":
    main()
