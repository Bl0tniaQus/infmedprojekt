 
from flask import Flask, render_template, session, request, redirect, url_for,send_file
from flask_session import Session
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Crypto.PublicKey import RSA
import joblib
import hashlib
import psycopg2
import os,shutil
from werkzeug.utils import secure_filename
def dbConnect():
    dbConnection = psycopg2.connect(host='localhost',database='infmed',user='postgres',password='postgres')
    return dbConnection
def cleantmp(login):
	if os.path.exists("./tmp/"+login+"private.pem"):
		os.remove("./tmp/"+login+"private.pem")
	if os.path.exists('./tmp/'+login):
		shutil.rmtree('./tmp/'+login) 
	if os.path.exists('./tmp/'+session["login"]+'aes.key'):
		os.remove('./tmp/'+session["login"]+'aes.key')
def usunwiad(idwiad):
	dbConnection = dbConnect()
	dbCursor = dbConnection.cursor()
	dbCursor.execute("SELECT autor,adresat FROM wiadomosc WHERE id_wiadomosci = '{}';".format(idwiad))
	users = dbCursor.fetchall()
	if len(users)!=0:
		if users[0][0]==session['userid'] or users[0][1]==session['userid']:
			dbCursor.execute("DELETE FROM zalacznik WHERE id_wiadomosci = '{}';".format(idwiad))
			dbCursor.execute("DELETE FROM wiadomosc WHERE id_wiadomosci = '{}';".format(idwiad))
			dbConnection.commit()
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "./tmp/"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/')
def index():
	if 'login' in session:
		return redirect("/skrzynkaodbiorcza")
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
		login = request.form["login"].lower()
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
				cleantmp(login)
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
		login = request.form["nazwa_uzytkownika"].lower()
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
				return render_template("rejestracja.html", msg=msg)
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
	return render_template("rejestracja.html", msg=msg)
	
@app.route('/downloadrsa', methods=["POST"])
def downloadrsa():
	if not request:
		return redirect("/")
	return send_file(request.form['downloadrsa'])
		
@app.route('/wyloguj')
def wyloguj():
	if 'login' in session:
		cleantmp(session['login'])
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
	adresaci = adresat.lower().split()
	szyfr = int(request.form["szyfr"])
	tresc_oryginal = request.form["tresc"]
	tytul = request.form["tytul"]
	msg=""
	zal=0
	if request.files['zalacznik'].filename!="":
		zal=1
	if szyfr==0:
		dbConnection = dbConnect()
		dbCursor = dbConnection.cursor()
		for user in adresaci:
			tresc = bytes(tresc_oryginal, 'utf-8')
			dbCursor.execute("SELECT id_uzytkownika FROM uzytkownik WHERE nazwa_uzytkownika = '{}';".format(user))
			iduser = dbCursor.fetchall()
			if len(iduser)==0:
				msg = msg + "Adresat o nazwie {} nie istnieje<br/>".format(user)
			else:
				iduser = iduser[0]
				dbCursor.execute('''INSERT INTO wiadomosc VALUES (default, %s, %s,%s,%s,%s,0,CURRENT_DATE,CURRENT_TIME,null) RETURNING id_wiadomosci''', (session['userid'], iduser, tytul, tresc,zal))
				idwiad = dbCursor.fetchall()[0]
				if request.files['zalacznik'].filename!="":
					zalacznik = request.files['zalacznik'].read()
					nazwa_pliku = secure_filename(request.files['zalacznik'].filename)
					dbCursor.execute('''INSERT INTO zalacznik VALUES (default, %s, %s,%s)''', (idwiad, bytes(zalacznik), nazwa_pliku))
				dbConnection.commit()
		dbCursor.close()
		dbConnection.close()
		return redirect("/skrzynkanadawcza")
	if szyfr==1:
		dbConnection = dbConnect()
		dbCursor = dbConnection.cursor()
		for user in adresaci:
			dbCursor.execute("SELECT id_uzytkownika,klucz_publiczny FROM uzytkownik WHERE nazwa_uzytkownika = '{}';".format(user))
			result = dbCursor.fetchall()
			print(result)
			iduser = result[0][0]
			public_key = bytes(result[0][1])
			if len(result)==0:
				msg = msg + "Adresat o nazwie {} nie istnieje<br/>".format(user)
			else:
				aeskey = get_random_bytes(16)
				iv = get_random_bytes(16)
				aes = AES.new(aeskey, AES.MODE_CBC, iv)
				tresc = aes.encrypt(pad(bytes(tresc_oryginal,'utf-8'),16))
				public_key = RSA.importKey(public_key)
				cipher_rsa = PKCS1_OAEP.new(public_key)
				aeskey2 = cipher_rsa.encrypt(aeskey)
				dbCursor.execute('''INSERT INTO wiadomosc VALUES (default, %s, %s,%s,%s,%s,1,CURRENT_DATE,CURRENT_TIME,%s,%s) RETURNING id_wiadomosci''', (session['userid'], iduser, tytul, tresc,zal,iv,aeskey2))
				idwiad = dbCursor.fetchall()[0]
				if request.files['zalacznik'].filename!="":
					zalacznik = request.files['zalacznik'].read()
					zalacznik = aes.encrypt(pad(zalacznik,16))
					nazwa_pliku = secure_filename(request.files['zalacznik'].filename)
					dbCursor.execute('''INSERT INTO zalacznik VALUES (default, %s, %s,%s)''', (idwiad, zalacznik, nazwa_pliku))
				dbConnection.commit()
		dbCursor.close()
		dbConnection.close()
		return redirect("/skrzynkanadawcza")
	if szyfr==2:
		dbConnection = dbConnect()
		dbCursor = dbConnection.cursor()
		try:
			keyfile = request.files["kluczaes"]
			nazwa_pliku = secure_filename(keyfile.filename)
			keyfile.save(app.config['UPLOAD_FOLDER']+nazwa_pliku)
			key = joblib.load('./tmp/'+nazwa_pliku)
			os.remove(app.config['UPLOAD_FOLDER'] + nazwa_pliku)
			iv = get_random_bytes(16)
			aes = AES.new(key, AES.MODE_CBC, iv)
			tresc = aes.encrypt(pad(bytes(tresc_oryginal,'utf-8'),16))
			for user in adresaci:
				dbCursor.execute("SELECT id_uzytkownika FROM uzytkownik WHERE nazwa_uzytkownika = '{}';".format(user))
				iduser = dbCursor.fetchall()[0]
				if len(iduser)==0:
					msg = msg + "Adresat o nazwie {} nie istnieje<br/>".format(user)
				else:
					dbCursor.execute('''INSERT INTO wiadomosc VALUES (default, %s, %s,%s,%s,%s,2,CURRENT_DATE,CURRENT_TIME,%s) RETURNING id_wiadomosci''', (session['userid'], iduser, tytul, tresc,zal,iv))
					idwiad = dbCursor.fetchall()[0]
					if request.files['zalacznik'].filename!="":
						zalacznik = request.files['zalacznik'].read()
						zalacznik = aes.encrypt(pad(zalacznik,16))
						nazwa_pliku = secure_filename(request.files['zalacznik'].filename)
						dbCursor.execute('''INSERT INTO zalacznik VALUES (default, %s, %s,%s)''', (idwiad, zalacznik, nazwa_pliku))
					dbConnection.commit()
			dbCursor.close()
			dbConnection.close()
			return redirect("/skrzynkanadawcza")
		except:
			msg = msg + "Wystąpił błąd"
	return render_template("wyslij.html",msg=msg)
@app.route("/profil")
def profil():
	if 'login' not in session:
		return redirect("/")
	return render_template("profil.html")
@app.route("/downloadaes")
def downloadaes():
	if 'login' not in session:
		return redirect("/")
	if os.path.exists('./tmp/'+session["login"]+'aes.key'):
		os.remove('./tmp/'+session["login"]+'aes.key')
	key = get_random_bytes(16)
	joblib.dump(key, './tmp/'+session["login"]+'aes.key')
	return send_file('./tmp/'+session["login"]+'aes.key')
@app.route("/skrzynkaodbiorcza")
def skrzynkaodbiorcza():
	if 'login' not in session:
		return redirect("/")
	if 'login' in session:
		cleantmp(session['login'])
	dbConnection = dbConnect()
	dbCursor = dbConnection.cursor()
	dbCursor.execute("SELECT id_wiadomosci,autor,adresat,tytul,tresc,zalacznik,szyfr,data_dodania,godzina_dodania,aesiv,aesrsa,nazwa_uzytkownika FROM wiadomosc INNER JOIN uzytkownik on id_uzytkownika=autor WHERE adresat = '{}' ORDER BY data_dodania DESC,id_wiadomosci DESC;".format(session['userid']))
	wiadomosci = dbCursor.fetchall()
	dbCursor.close()
	dbConnection.close()
	return render_template("skrzynkaodbiorcza.html", wiadomosci=wiadomosci,dl = len(wiadomosci))
@app.route("/skrzynkanadawcza")
def skrzynkanadawcza():
	if 'login' not in session:
		return redirect("/")
	if 'login' in session:
		cleantmp(session['login'])
	dbConnection = dbConnect()
	dbCursor = dbConnection.cursor()
	dbCursor.execute("SELECT id_wiadomosci,autor,adresat,tytul,tresc,zalacznik,szyfr,data_dodania,godzina_dodania,aesiv,aesrsa,nazwa_uzytkownika FROM wiadomosc INNER JOIN uzytkownik on id_uzytkownika=adresat WHERE adresat = '{}' ORDER BY data_dodania DESC,id_wiadomosci DESC;".format(session['userid']))
	wiadomosci = dbCursor.fetchall()
	dbCursor.close()
	dbConnection.close()
	return render_template("skrzynkanadawcza.html", wiadomosci=wiadomosci,dl = len(wiadomosci))
@app.route("/wiadomosc", methods=["POST"])
def wiadomosc():
	if 'login' not in session or request.method !="POST":
		return redirect("/")
	dbConnection = dbConnect()
	dbCursor = dbConnection.cursor()
	dbCursor.execute("SELECT id_wiadomosci,autor,adresat,tytul,tresc,zalacznik,szyfr,data_dodania,godzina_dodania,aesiv,aesrsa,nazwa_uzytkownika FROM wiadomosc INNER JOIN uzytkownik on id_uzytkownika=autor WHERE id_wiadomosci = '{}';".format(request.form['wiadomosc']))
	wiad = dbCursor.fetchall()
	dbCursor.execute("SELECT * from zalacznik WHERE id_wiadomosci = {}".format(request.form['wiadomosc']))
	zal = dbCursor.fetchall()
	wiadomosc = []
	zalacznik = []
	for x in wiad[0]:
		wiadomosc.append(x)
	if wiadomosc[2]!=session['userid']:
		return redirect("/")
	if wiadomosc[6]==0:
		if len(zal)!=0:
			for x in zal[0]:
				zalacznik.append(x)
			zal = [1, zal[0][3]]
		else:
			zal = []
		wiadomosc[4]=bytes(wiadomosc[4]).decode('utf-8')
	dbCursor.close()
	dbConnection.close()
	return render_template("wiadomosc.html", wiadomosc=wiadomosc, zal=zal)
@app.route("/wiadomoscrsa", methods=["POST"])
def wiadomoscrsa():
	if 'login' not in session or request.method !="POST":
		return redirect("/")
	dec=0
	msg=""
	dbConnection = dbConnect()
	dbCursor = dbConnection.cursor()
	dbCursor.execute("SELECT id_wiadomosci,autor,adresat,tytul,tresc,zalacznik,szyfr,data_dodania,godzina_dodania,aesiv,aesrsa,nazwa_uzytkownika FROM wiadomosc INNER JOIN uzytkownik on id_uzytkownika=autor WHERE id_wiadomosci = '{}';".format(request.form['rsa']))
	wiad = dbCursor.fetchall()
	dbCursor.execute("SELECT * from zalacznik WHERE id_wiadomosci = {}".format(request.form['rsa']))
	zal = dbCursor.fetchall()
	wiadomosc = []
	zalacznik = []
	for x in wiad[0]:
		wiadomosc.append(x)
	if wiadomosc[2]!=session['userid']:
		return redirect("/")
	if wiadomosc[6]==1:
		if len(zal)!=0:
			for x in zal[0]:
				zalacznik.append(x)
			zal = [1, zal[0][3]]
		else:
			zal = []
		try:
			aesrsa = bytes(wiadomosc[10])
			keyfile = request.files["rsakey"]
			nazwa_pliku = secure_filename(keyfile.filename)
			keyfile.save(app.config['UPLOAD_FOLDER']+nazwa_pliku)
			with open(app.config['UPLOAD_FOLDER']+nazwa_pliku, "r") as f:
				key = f.read()
			os.remove(app.config['UPLOAD_FOLDER'] + nazwa_pliku)
			wiadomosc[4]=bytes(wiadomosc[4])
			privatekey = RSA.importKey(key)
			cipher_rsa = PKCS1_OAEP.new(privatekey)
			aeskey = cipher_rsa.decrypt(aesrsa)
			aes = AES.new(aeskey, AES.MODE_CBC, bytes(wiadomosc[9]))
			wiadomosc[4] = unpad(aes.decrypt(wiadomosc[4]),16).decode('utf-8')
			if len(zal)!=0:
				zalacznik[2] = unpad(aes.decrypt(bytes(zalacznik[2])),16)
				if not os.path.exists('./tmp/'+session['login']):
					os.mkdir('./tmp/'+session['login'])
				if os.path.exists('./tmp/'+session['login']+'/'+zalacznik[3]):
					os.remove('./tmp/'+session['login']+'/'+zalacznik[3])
				with open('./tmp/'+session['login']+'/'+zalacznik[3], "wb") as f:
					f.write(zalacznik[2])
			dec=1
		except:
			msg = "Niepoprawny klucz"
	dbCursor.close()
	dbConnection.close()
	return render_template("wiadomosc.html",wiadomosc=wiadomosc,msg=msg,dec=dec, zal=zal)
@app.route("/wiadomoscaes", methods=["POST"])
def wiadomoscaes():
	if 'login' not in session or request.method !="POST":
		return redirect("/")
	dec=0
	msg=""
	dbConnection = dbConnect()
	dbCursor = dbConnection.cursor()
	dbCursor.execute("SELECT id_wiadomosci,autor,adresat,tytul,tresc,zalacznik,szyfr,data_dodania,godzina_dodania,aesiv,nazwa_uzytkownika FROM wiadomosc INNER JOIN uzytkownik on id_uzytkownika=autor WHERE id_wiadomosci = '{}';".format(request.form['aes']))
	wiad = dbCursor.fetchall()
	wiadomosc = []
	dbCursor.execute("SELECT * from zalacznik WHERE id_wiadomosci = {}".format(request.form['aes']))
	zal = dbCursor.fetchall()
	zalacznik = []
	for x in wiad[0]:
		wiadomosc.append(x)
	if wiadomosc[2]!=session['userid']:
		return redirect("/")
	if wiadomosc[6]==2:
		if len(zal)!=0:
			for x in zal[0]:
				zalacznik.append(x)
			zal = [1, zal[0][3]]
		else:
			zal = []
		try:
			keyfile = request.files["aeskey"]
			nazwa_pliku = secure_filename(keyfile.filename)
			keyfile.save(app.config['UPLOAD_FOLDER']+nazwa_pliku)
			key = joblib.load(app.config['UPLOAD_FOLDER'] + nazwa_pliku)
			os.remove(app.config['UPLOAD_FOLDER'] + nazwa_pliku)
			wiadomosc[4]=bytes(wiadomosc[4])
			aes = AES.new(key, AES.MODE_CBC, bytes(wiadomosc[9]))
			wiadomosc[4] = unpad(aes.decrypt(wiadomosc[4]),16).decode('utf-8')
			if len(zal)!=0:
				zalacznik[2] = unpad(aes.decrypt(bytes(zalacznik[2])),16)
				if not os.path.exists('./tmp/'+session['login']):
					os.mkdir('./tmp/'+session['login'])
				if os.path.exists('./tmp/'+session['login']+'/'+zalacznik[3]):
					os.remove('./tmp/'+session['login']+'/'+zalacznik[3])
				with open('./tmp/'+session['login']+'/'+zalacznik[3], "wb") as f:
					f.write(zalacznik[2])
			dec=1
		except:
			msg = "Niepoprawny klucz"
	dbCursor.close()
	dbConnection.close()
	return render_template("wiadomosc.html",wiadomosc=wiadomosc,msg=msg,dec=dec,zal=zal)
@app.route("/pobierz", methods=["POST"])
def pobierz():
	if 'login' not in session or request.method !="POST":
		return redirect("/")
	dbConnection = dbConnect()
	dbCursor = dbConnection.cursor()
	dbCursor.execute("SELECT * FROM zalacznik WHERE id_wiadomosci = '{}';".format(request.form['pobierz']))
	zal = dbCursor.fetchall()
	dbCursor.execute("SELECT adresat,szyfr FROM wiadomosc WHERE id_wiadomosci = '{}'".format(request.form['pobierz']))
	res = dbCursor.fetchall()
	userid = res[0][0]
	zalacznik = []
	for x in zal[0]:
		zalacznik.append(x)
	if res[0][1] == 0:
		if userid[0]!=session['userid']:
			return redirect("/")
		if not os.path.exists('./tmp/'+session['login']):
			os.mkdir('./tmp/'+session['login'])
		if os.path.exists('./tmp/'+session['login']+'/'+zalacznik[3]):
			os.remove('./tmp/'+session['login']+'/'+zalacznik[3])
		if not os.path.exists('./tmp/'+session['login']+'/'+zalacznik[3]):
			with open('./tmp/'+session['login']+'/'+zalacznik[3], "wb") as f:
				f.write(bytes(zalacznik[2]))
	dbCursor.close()
	dbConnection.close()
	return send_file('./tmp/'+session['login']+'/'+zalacznik[3], as_attachment=True)
@app.route("/usunodb", methods=["POST"])
def usunodb():
	if 'login' not in session or request.method !="POST":
		return redirect("/")
	usunwiad(request.form['wiadomosc'])
	return redirect("/skrzynkaodbiorcza")
@app.route("/usunnad", methods=["POST"])
def usunnad():
	if 'login' not in session or request.method !="POST":
		return redirect("/")
	usunwiad(request.form['wiadomosc'])
	return redirect("/skrzynkanadawcza")
	

if __name__ == "__main__":
    app.run(debug=True)
