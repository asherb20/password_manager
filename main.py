import json
from getpass import getpass
import uuid
import bcrypt

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
    if email == u['email'] and pwd == bcrypt.checkpw(str.encode(pwd), str.encode(u['password'])):
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
  hashed = bcrypt.hashpw(str.encode(pwd), salt)
  user = {
    'id': str(uuid.uuid4()),
    'email': email,
    'password': str(hashed)
  }
  db = get_db()
  users = db['users']
  users.append(user)
  db['users'] = users
  write_db(db)
  return None

# app
def login():
  print('# Login')
  email = input('Enter your email: ')
  pwd = getpass('Enter your password: ')
  user = auth_user(email, pwd)
  if user == None:
    print('## Invalid credentials.')
    login()
  else:
    print('## Logged in successfully.')
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
  pwd = getpass('Enter your password: ')
  create_user(email, pwd)
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