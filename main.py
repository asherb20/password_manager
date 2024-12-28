import json
import uuid
import bcrypt
import base64
import secrets
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# modules
def get_db():
  with open('db.json', 'r') as f:
    db = json.loads(f.read())
    f.close()
    return db
  
def write_db(data):
  with open('db.json', 'w') as f:
    f.write(json.dumps(data))
    f.close()

def auth_user(email, pwd):
  db = get_db()
  users = db['users']
  user = None
  for u in users:
    if email == u['email'] and bcrypt.checkpw(pwd.encode('utf-8'), u['password'].encode('utf-8')):
      user = u
  return user

def user_exists(email):
  db = get_db()
  users = db['users']
  user_exists = False
  for u in users:
    if email == u['email']:
      user_exists = True
      break
  return user_exists

def create_user(email, pwd):
  salt = bcrypt.gensalt()
  hashed = bcrypt.hashpw(pwd.encode('utf-8'), salt)
  user = {
    'id': str(uuid.uuid4()),
    'email': email,
    'password': hashed.decode('utf-8'),
    'salt': salt.decode('utf-8')
  }
  db = get_db()
  users = db['users']
  users.append(user)
  db['users'] = users
  write_db(db)
  return user

def get_safe_key(password, salt):
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt.encode('utf-8'),
    iterations=100000
  )
  key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
  return key

def write_safe(user_id, data, password, salt):
  key = get_safe_key(password, salt)
  cipher_suite = Fernet(key)
  encrypted_data = cipher_suite.encrypt(json.dumps(data).encode('utf-8'))
  safe = {
    'user_id': user_id,
    'data': encrypted_data.decode('utf-8')
  }
  db = get_db()
  safes = db['safes']
  index = None
  # get index of existing safe
  for i, s in enumerate(safes):
    if s.get('user_id') == user_id:
      index = i
      break
  # add safe if not found, replace safe if found
  if index == None:
    safes.append(safe)
  else:
    safes[index] = safe
  db['safes'] = safes
  write_db(db)
  return safe

def open_safe(user_id, password, salt):
  db = get_db()
  safes = db['safes']
  safe = None
  for s in safes:
    if s.get('user_id') == user_id:
      safe = s
      break
  if safe == None:
    safe = write_safe(user_id, {}, password, salt)
  key = get_safe_key(password, salt)
  cipher_suite = Fernet(key)
  decrypted_bytes = cipher_suite.decrypt(safe['data'])
  data = json.loads(decrypted_bytes.decode('utf-8'))
  return data

def generate_password():
  password_length = input('Input the desired password length (defaults to 12 if left blank): ')
  try:
    if password_length == None or password_length == '':
      password_length = 12
    else:
      password_length = int(password_length)
  except ValueError:
    print('!! Value must be an integer.')
    return generate_password()
  return secrets.token_urlsafe(password_length)

# app
def user_safe_screen(user_id, password, salt, data = None):
  if data == None:
    data = open_safe(user_id, password, salt)
  stored_passwords = data.get('passwords')
  if stored_passwords == None:
    stored_passwords = []

  print('## Your stored passwords:')
  for sp in stored_passwords:
    print(f"> Name: {sp['name']}, Username: {sp['username']}")

  print('## Enter "1" to create a password.')
  print('## Enter "2" to read a password.')
  print('## Enter "3" to update a password.')
  print('## Enter "4" to delete a password.')
  print('## Enter "5" to save and logout.')
  i = input('Input an option and press enter: ')

  if i == '1':
    print('## Create password')
    stored_password = {
      'name': input('Unique name: '),
      'url': input('URL: '),
      'username': input('Username: ')
    }
    new_password = input('Password (enter "gen" to generate a strong password): ')
    if new_password == 'gen':
      stored_password['password'] = generate_password()
    stored_passwords.append(stored_password)
  elif i == '2':
    print('## Read password')
    name = input('Input the name of the password you want to read: ')
    for sp in stored_passwords:
      if sp.get('name') == name:
        print(f"> Name: {sp['name']}")
        print(f"> URL: {sp['url']}")
        print(f"> Username: {sp['username']}")
        print(f"> Password: {sp['password']}")
        break
  elif i == '3':
    print('## Update password')
    name = input('Input the name of the password you want to update: ')
    for i, sp in enumerate(stored_passwords):
      if sp.get('name') == name:
        updated_stored_password = sp

        updated_name = input(f"Update Name (current: {sp.get('name')} [enter nothing to leave as-is]): ")
        if updated_name != None and updated_name != '':
          updated_stored_password['name'] = updated_name    

        updated_url = input(f"Update URL (current: {sp.get('url')} [enter nothing to leave as-is]): ")
        if updated_url != None and updated_url != '':
          updated_stored_password['url'] = updated_url 
        
        updated_username = input(f"Update Username (current: {sp.get('username')} [enter nothing to leave as-is]): ")
        if updated_username != None and updated_username != '':
          updated_stored_password['username'] = updated_username
        
        updated_password = input(f"Update Password (current: {sp.get('password')} [enter \"gen\" to generate a strong password or enter nothing to leave as-is]): ")
        if updated_password != None and updated_password != '':
          if updated_password == 'gen':
            updated_stored_password['password'] = generate_password()
          else:
            updated_stored_password['password'] = updated_password

        stored_passwords[i] = updated_stored_password

        print('## Password updated.')

        break
  elif i == '4':
    print('## Delete password')
    name = input('Input the name of the password you want to update: ')
    for i, sp in enumerate(stored_passwords):
      if sp.get('name') == name:
        stored_passwords.pop(i)
        print('## Password deleted.')
        break
  elif i == '5':
    print('## Saving and logging out')
    data['passwords'] = stored_passwords
    write_safe(user_id, data, password, salt)
    return None
  else:
    print('## Invalid option')
  
  return user_safe_screen(user_id, password, salt, data)

def login_screen():
  print('# Login')
  email = input('Enter your email: ')
  pwd = getpass('Enter your master password: ')
  user = auth_user(email, pwd)
  if user == None:
    print('## Invalid credentials.')
    login_screen()
  else:
    print('## Logged in successfully.')
    user_safe_screen(user['id'], pwd, user['salt'])
  return None

def create_account_screen():
  print('# Create account')
  email = input('Enter your email: ')
  if email == None or email == '':
    print('## Email cannot be blank.')
    create_account_screen()
  if user_exists(email) == True:
    print('## Email already exists.')
    create_account_screen()
  pwd = getpass('Enter your master password: ')
  user = create_user(email, pwd)
  write_safe(user['id'], {}, pwd, user['salt'])
  return None

# main
def main():
  print('# Welcome to password manager!')
  print('## Enter "1" to log into your safe.')
  print('## Enter "2" to create a new account.')
  print('## Enter "3" to reset your password.')

  i = input('Input an option and press enter: ')

  if i == '1':
    login_screen()
  elif i == '2':
    create_account_screen()
    login_screen()
  elif i == '3':
    print('# Reset password')
  else:
    print('# Invalid input')
  main()

main()