import json
import uuid
import bcrypt
import base64
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
  print('## Opening safe.')
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

# app
def login():
  print('# Login')
  email = input('Enter your email: ')
  pwd = getpass('Enter your master password: ')
  user = auth_user(email, pwd)
  if user == None:
    print('## Invalid credentials.')
    login()
  else:
    print('## Logged in successfully.')
    data = open_safe(user['id'], pwd, user['salt'])
    print(data)
  return None

def create_account():
  print('# Create account')
  email = input('Enter your email: ')
  if email == None or email == '':
    print('## Email cannot be blank.')
    create_account()
  if user_exists(email) == True:
    print('## Email already exists.')
    create_account()
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
    login()
  elif i == '2':
    create_account()
    login()
  elif i == '3':
    print('# Reset password')
  else:
    print('# Invalid input')
  exit()

main()