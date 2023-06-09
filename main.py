from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session
import hashlib
import psycopg2
def dbConnect():
    dbConnection = psycopg2.connect(host='localhost',database='infmed',user='postgres',password='postgres')
    return dbConnection
    
app = Flask(__name__)
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
				haslo = hashlib.sha256(haslo.encode('utf-8')).hexdigest()
				dbCursor.execute("INSERT INTO uzytkownik VALUES (default, '{}', '{}', CURRENT_DATE);".format(login,haslo))
				dbConnection.commit()
				msg = "Konto utworzone prawidłowo"
			dbCursor.close()
			dbConnection.close()
	return render_template("rejestracja.html", msg=msg)	
@app.route('/wyloguj')
def wyloguj():
	session.clear()
	return redirect("/")
	
	
if __name__ == "__main__":
    app.run(debug=True)
