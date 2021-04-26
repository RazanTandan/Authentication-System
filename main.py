from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = '716151ecd8eb81be790673124d56cfdf08'
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# Methods for Routing
@app.route('/register', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmpassword']

        if not name or not email or not password or not confirm_password:
            flash('Please check your signup details and try again.')
            return redirect(url_for("register"))
        user = RegisterModel.query.filter_by(email=email).first()

        if user:
            flash('Email address already exists.')
            return redirect(url_for("register"))

        if password == confirm_password:
            db.session.add(RegisterModel(name=name, email=email,
                                         password=generate_password_hash(password, method='sha256')))
            db.session.commit()
            return redirect(url_for("login"))
        else:
            flash("Password don't match with confirm password")
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        check = request.form.get('tick', False)
        if check == 'on':
            check = True

        user = RegisterModel.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            redirect(url_for("login"))
        else:
            login_user(user, remember=check)
            return redirect(url_for('profile'))
    return render_template("login.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('profile'))


@app.route('/')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

# Database Models
@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return RegisterModel.query.get(int(user_id))

class RegisterModel(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(140), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"(name : {self.name}, email : {self.email}, password : {self.password})"


if __name__ == '__main__':
    app.run(debug=True)