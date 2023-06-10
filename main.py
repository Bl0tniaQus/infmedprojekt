from flask import Flask, render_template, session, request, redirect, url_for,send_file
from flask_session import Session
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Crypto.PublicKey import RSA
import joblib
import hashlib
import psycopg2
import os
from werkzeug.utils import secure_filename
def dbConnect():
    dbConnection = psycopg2.connect(host='localhost',database='infmed',user='postgres',password='postgres')
    return dbConnection
    
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "./tmp/"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/')
def index():
	return render_template("index.html")
@app.route('/logowanie')
def logowanie():
	if 'login' in session:
		return redirect("/")
	return render_template("logowanie.html")
@app.route('/logowanie_action', methods=["POST"])
def logowanie_action():
	if 'login' in session:
		return redirect("/")
	if request.method == "POST":
		login = request.form["login"]
		haslo = request.form["haslo"]
		if login=="" or haslo=="":
			msg = "Nie wszystkie pola zostały wypełnione"
		else:
			haslo = hashlib.sha256(haslo.encode('utf-8')).hexdigest()
			dbConnection = dbConnect()
			dbCursor = dbConnection.cursor()
			dbCursor.execute("SELECT id_uzytkownika, haslo FROM uzytkownik WHERE nazwa_uzytkownika = '{}'".format(login))
			haslo2 = dbCursor.fetchall()
			if len(haslo2)==0 or haslo!=haslo2[0][1]:
				msg = "Niepoprawne dane logowania"
			else:
				session['login'] = login
				session['userid'] = haslo2[0][0]
				if os.path.exists("./tmp/"+login+"private.pem"):
					os.remove("./tmp/"+login+"private.pem")
				return redirect("/")
		return render_template("logowanie.html", msg=msg)	
	return render_template("logowanie.html")
	
@app.route('/rejestracja')
def rejestracja():
	if 'login' in session:
		return redirect("/")
	return render_template("rejestracja.html")
	
@app.route('/rejestracja_action', methods=['POST'])
def rejestracja_action():
	if 'login' in session:
		return redirect("/")
	if request.method == "POST":
		login = request.form["nazwa_uzytkownika"]
		haslo = request.form["haslo"]
		haslo2 = request.form["haslo2"]	
		if haslo != haslo2:
			msg = "Hasła nie są takie same"
		elif login=="" or haslo=="" or haslo2=="":
			msg = "Nie wszystkie pola zostały wypełnione"
		else:
			dbConnection = dbConnect()
			dbCursor = dbConnection.cursor()

			dbCursor.execute("SELECT nazwa_uzytkownika FROM uzytkownik WHERE nazwa_uzytkownika = '{}';".format(login))
			check = dbCursor.fetchall()
			if len(check)!=0:
				msg = "Istnieje już użytkownik o podanej nazwie"
			else:
				
				key = RSA.generate(2048)
				private_key = key.exportKey()
				with open("./tmp/"+login+"private.pem", "wb") as f:
					f.write(private_key)
				public_key = key.publickey().exportKey()
				
				haslo = hashlib.sha256(haslo.encode('utf-8')).hexdigest()
				dbCursor.execute('''INSERT INTO uzytkownik VALUES (default, %s, %s, %s, CURRENT_DATE)''', (login, haslo, public_key))
				dbConnection.commit()
				msg = "Konto utworzone prawidłowo"
			dbCursor.close()
			dbConnection.close()
	return render_template("witamy.html", msg=msg,filename="./tmp/"+login+"private.pem")
@app.route('/downloadrsa', methods=["POST"])
def downloadrsa():
	if not request:
		return redirect("/")
	return send_file(request.form['downloadrsa'])
		
@app.route('/wyloguj')
def wyloguj():
	session.clear()
	return redirect("/")
@app.route('/wyslij')
def wyslij():
	if 'login' not in session:
		return redirect("/")
	return render_template("wyslij.html")
@app.route('/wyslijaction', methods=["POST"])
def wyslijaction():
	if 'login' not in session:
		return redirect("/")
	adresat = request.form["adresat"]
	adresaci = adresat.split()
	szyfr = int(request.form["szyfr"])
	tresc = request.form["tresc"]
	tytul = request.form["tytul"]
	msg=""
	if szyfr==0:
		dbConnection = dbConnect()
		dbCursor = dbConnection.cursor()
		for user in adresaci:
			tresc = bytes(tresc, 'utf-8')
			dbCursor.execute("SELECT id_uzytkownika FROM uzytkownik WHERE nazwa_uzytkownika = '{}';".format(user))
			iduser = dbCursor.fetchall()[0]
			if len(iduser)==0:
				msg = "Adresat o nazwie {user} nie istnieje\n"
			else:
				dbCursor.execute('''INSERT INTO wiadomosc VALUES (default, %s, %s,%s,%s,0,0,CURRENT_DATE,null)''', (session['userid'], iduser, tytul, tresc))
				dbConnection.commit()
		dbCursor.close()
		dbConnection.close()
	if szyfr==1:
		dbConnection = dbConnect()
		dbCursor = dbConnection.cursor()
		for user in adresaci:
			dbCursor.execute("SELECT id_uzytkownika,klucz_publiczny FROM uzytkownik WHERE nazwa_uzytkownika = '{}';".format(user))
			result = dbCursor.fetchall()
			iduser = result[0][0]
			public_key = bytes(result[0][1])
			if len(result)==0:
				msg = "Adresat o nazwie {user} nie istnieje\n"
			else:
				public_key = RSA.importKey(public_key)
				cipher_rsa = PKCS1_OAEP.new(public_key)
				tresc = cipher_rsa.encrypt(bytes(tresc,'utf-8'))
				dbCursor.execute('''INSERT INTO wiadomosc VALUES (default, %s, %s,%s,%s,0,1,CURRENT_DATE,null)''', (session['userid'], iduser, tytul, tresc))
				dbConnection.commit()
		dbCursor.close()
		dbConnection.close()
	if szyfr==2:
		keyfile = request.files["kluczaes"]
		nazwa_pliku = secure_filename(keyfile.filename)
		keyfile.save(app.config['UPLOAD_FOLDER']+nazwa_pliku)
		key = joblib.load('./tmp/'+nazwa_pliku)
		os.remove(app.config['UPLOAD_FOLDER'] + nazwa_pliku)
		iv = get_random_bytes(16)
		aes = AES.new(key, AES.MODE_CBC, iv)
		tresc = aes.encrypt(pad(bytes(tresc,'utf-8'),16))
		
		dbConnection = dbConnect()
		dbCursor = dbConnection.cursor()
		for user in adresaci:
			dbCursor.execute("SELECT id_uzytkownika FROM uzytkownik WHERE nazwa_uzytkownika = '{}';".format(user))
			iduser = dbCursor.fetchall()[0]
			if len(iduser)==0:
				msg = "Adresat o nazwie {user} nie istnieje\n"
			else:
				#aes = AES.new(key, AES.MODE_CBC, iv)
				#xd = unpad(aes.decrypt(tresc),16).decode('utf-8')
				dbCursor.execute('''INSERT INTO wiadomosc VALUES (default, %s, %s,%s,%s,0,2,CURRENT_DATE,%s)''', (session['userid'], iduser, tytul, tresc,iv))
				dbConnection.commit()
		dbCursor.close()
		dbConnection.close()
	return redirect("/")
@app.route("/profil")
def profil():
	if 'login' not in session:
		return redirect("/")
	return render_template("profil.html")
@app.route("/downloadaes")
def downloadaes():
	if 'login' not in session:
		return redirect("/")
	if os.path.exists('./tmp/aeskey.key'):
		os.remove('./tmp/aeskey.key')
	key = get_random_bytes(16)
	joblib.dump(key, './tmp/aeskey.key')
	return send_file('./tmp/aeskey.key')
if __name__ == "__main__":
    app.run(debug=True)
