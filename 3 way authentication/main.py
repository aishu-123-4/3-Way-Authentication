from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import string, random
import auth
from flask_bcrypt import Bcrypt


app = Flask(__name__)

app.secret_key = 'your secret key'

app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '******'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_DB'] = 'three_way_auth'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
counter_list = [50]

def random_string():
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(letters_and_digits) for i in range(64)))
    return result_str

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')
    
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/register', methods =['GET', 'POST'])
def register():
    if 'loggedin' in session:
        return redirect(url_for('home'))
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form : 
        username = request.form['username'] 
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password) 
        email = request.form['email']
        secret = random_string()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor) 
        cursor.execute('SELECT * FROM login WHERE username = %s', (username,)) 
        account = cursor.fetchone() 
        if account: 
            msg = 'Account already exists !'
            return render_template('register.html', msg=msg)
        else: 
            cursor.execute('INSERT INTO login VALUES (% s, % s, % s, %s)', (username, email, hashed_password, secret,)) 
            mysql.connection.commit()
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods =['GET', 'POST']) 
def login():
    if 'loggedin' in session:
        return redirect(url_for('home'))
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form: 
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor) 
        cursor.execute('SELECT * FROM login WHERE email = %s', (email,)) 
        account = cursor.fetchone() 
        if account and bcrypt.check_password_hash(account["password"], password): 
            session['tryloggedin'] = True
            session['secret'] = account['secret'] 
            return redirect(url_for('otp'))
        else: 
            msg = 'Incorrect email / password !'
            return render_template('login.html', msg = msg)
    return render_template('login.html')

@app.route("/logout")
def logout():
   session.pop('loggedin', None)
   session.pop('tryloggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   return redirect(url_for('home'))

@app.route("/otp", methods =['GET', 'POST'])
def otp():
    if 'loggedin' in session:
        return redirect(url_for('home'))
    if 'tryloggedin' not in session:
        return redirect(url_for('login'))

    key = session['secret'].encode('utf-8')
    hotp_access = False
    print(auth.HOTP(key,counter_list[-1]))
    print(auth.TOTP(key))

    if request.method == 'POST' and 'hotp' in request.form and 'totp' in request.form:
        hotp = request.form['hotp']
        totp = request.form['totp']

        for x in range(0,len(counter_list)):
            if len(counter_list) > 50:
                hotp_access = False
            if hotp == auth.HOTP(key,counter_list[x]):
                current_counter = counter_list[x]
                hotp_access = True
                break

        if hotp_access == True and totp == auth.TOTP(key):
            session['loggedin'] = True
            counter_list.clear()
            counter_list.append(current_counter + 1)
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect hotp / totp !'
            return render_template('otp.html', msg = msg)
    return render_template('otp.html')

@app.route("/tryagain")
def tryagain():
    counter_list.append(counter_list[-1]+1)
    return redirect(url_for('otp'))

if __name__ == '__main__':
	app.run(debug=True)