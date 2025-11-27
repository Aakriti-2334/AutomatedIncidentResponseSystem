from services import database_service

def main():
    print("Creating default user...")
    database_service.init_db()
    database_service.create_user('admin', 'password')

if __name__ == '__main__':
    main()
