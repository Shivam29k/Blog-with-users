from datetime import date as Date
from flask import Flask, abort, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, OTPForm
from sqlalchemy.exc import IntegrityError
import random
# from dotenv import load_dotenv
import os
import smtplib

# load_dotenv()

MY_MAIL = os.getenv('MY_MAIL')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_KEY')
Bootstrap5(app)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)



# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
db = SQLAlchemy()
db.init_app(app)



# CONFIGURE TABLES
# User table for all your registered users.
# Video tutorial on relationship patterns: https://www.nsfwyoutube.com/watch?v=VVX7JIWx-ss

class User(UserMixin, db.Model):  # Parent
    __tablename__ = "users"  # Name of the table
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    # Create reference to the BlogPost class - "author" refers to the author property in the BlogPost class
    # posts is a "pseudo column" in this "users" table
    # For example, you could use user.posts to retrieve the list of posts that user has created
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="author")

class BlogPost(db.Model):  # Child
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
     # ForeignKey refers to the primary key in the other *table* (users)
    # author_id is a real column in this "blog_posts" table
    # Without the ForeignKey, the relationships would not work.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # Create reference to the User class - "posts" refers to the posts property in the User class
    # author is a "pseudo column" in this "blog_posts" table
    # For example, you could use blog_post.author to retrieve the user who created the post
    author=db.relationship("User", back_populates="posts")
    comments = db.relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author=db.relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    post=db.relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()

# Creating admin only decorator
def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.email != MY_MAIL:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return wrapper

def check_admin():
    if current_user.is_authenticated:
        if current_user.email == MY_MAIL:
            return True

# Creating Send mail function
def send_mail(mail, msg):
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(user=MY_MAIL, password=EMAIL_PASSWORD)
        connection.sendmail(
            from_addr=MY_MAIL,
            to_addrs=mail,
            msg=msg
        )

# Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    registerform = RegisterForm()
    otpform = OTPForm()

    if registerform.validate_on_submit():
        global new_user, otp
        email = registerform.Email.data
        new_user = User(
            email = registerform.Email.data,
            name = registerform.name.data,
            password = generate_password_hash(registerform.Password.data, method='pbkdf2:sha256', salt_length=8)
        )
        otp = random.randint(100000, 999999)
        msg = f"Subject: OTP for Blogs Website \n\n Your OTP is {otp}"
        send_mail(mail=email, msg=msg)
        return render_template("register.html", form = otpform)

    if otpform.validate_on_submit():
        print(otp)
        if int(otpform.OTP.data) == otp:
            try:
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                flash('Account created successfully')
                return redirect(url_for('get_all_posts'))
            except IntegrityError:
                db.session.rollback()
                flash('Email address already exists. Please login instead.')
                return redirect(url_for('login'))
        else:
            flash("""Retry, OTP did not match. <a href="/register">Register</a>""")
            return render_template("register.html", form = otpform)

    return render_template("register.html", form = registerform)


# Retrieve a user from the database based on their email.
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.Email.data).first()
        if not user:
            flash('Email does not exist, Registor first.', 'error')
            return redirect(url_for('register'))
        if check_password_hash(user.password, form.Password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Password incorrect, please try again.', 'error')
    return render_template("login.html", form = form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user, admin=check_admin())


# logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)

    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text = form.comment.data,
                author = current_user,
                post = requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash('You need to login or register to comment.', 'error')
            return redirect(url_for('login'))
    gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
    return render_template("post.html", post=requested_post, form=form, current_user=current_user, gravatar=gravatar, admin=check_admin())

# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=Date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == 'POST':
        data = request.form
        if data['name'] == '' and (data['email']=='' or data['phone_no']==''):
            flash('Please enter your name and either email or phone number')
        else:
            try:
                msg = f"Subject: Contact Details sent via Blogs Website \n\n Name : {data['name']} \nEmail : {data['email']} \nPhone_no : {data['phone_no']} \nMessage : {data['message']}"
                send_mail(mail=MY_MAIL, msg=msg)
                flash('Message sent successfully', 'success')
            except:
                flash('No message sent', 'Error')

    return render_template("contact.html", current_user=current_user)

@app.route("/shivam")
def namecard():
    return render_template("namecard.html")

if __name__ == "__main__":
    app.run(debug=True, port=5002)
