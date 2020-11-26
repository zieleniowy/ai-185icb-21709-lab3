## logowanie-rejestracja na zaliczenie laboratoriów z tworzenia aplikacji internetowych na amw - 185icb - 21709

aplikacja uruchomiona na heroku pod [tym](https://lab1-185icb-21709-ai.herokuapp.com/) adresem 

aby ją uruchomić, należy stworzyć w głównym folderze plik .env ze zmiennymi konfiguracyjnymi (lub dodać je przez panel konfiguracyjny, jeśli aplikacja instalowana jest np. na heroku). Ze względów bezpieczeństwa plik .env dodany jest do .gitignore.  
### lista zmiennych
- PORT
- SESSION_SECRET
- MAIL_AUTH_USER
- MAIL_AUTH_PASS
- MAIL_SMTP_SERVER
- MAIL_SMTP_PORT
- MAIL_FROM
- MONGO_CONNECTION_STRING
- MONGO_DB
- HASH_ROUNDS
- RESET_TOKEN_TIME
- JWT_SECRET

w zmiennej RESET_TOKEN_TIME, czas należy podać w sekundach