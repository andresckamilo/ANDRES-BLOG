from flask import Flask, render_template, redirect, url_for, flash, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import Registerform, CreatePostForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from dotenv import load_dotenv
import os
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
app = Flask(__name__)
Base = declarative_base()

load_dotenv()

login_manager = LoginManager()
error = ""

app.config['SECRET_KEY'] = os.environ.get("APP_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////pythonProject/Day69/blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous or current_user.id != 1:
            return abort(403, description="Resource not found")
        else:
            pass
        return function(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(1000), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    comments = relationship("Comment", back_populates="comment_blog")


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship('BlogPost', back_populates="author")
    comments = relationship('Comment', back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey("user.id"))
    comment_author = relationship('User', back_populates="comments")
    post_id = db.Column(db.Integer, ForeignKey("posts.id"))
    comment_blog = relationship("BlogPost", back_populates="comments")
    comment = db.Column(db.Text, nullable=False)


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    user = current_user
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user=user)


@app.route('/register', methods=["POST", "GET"])
def register():
    register = Registerform()

    if register.validate_on_submit():
        if User.query.filter_by(email=register.email.data).first():
            flash(u'You already signed up with that email, try log in instead.')
            return redirect(url_for('login'))
        else:
            password = generate_password_hash(register.password.data,
                                              method='pbkdf2:sha256',
                                              salt_length=8)
            new_user = User(email=register.email.data, password=password, name=register.name.data)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register, logged_in=current_user.is_authenticated, error=error)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user is None:
            flash(u'That email does not exist, please try again.')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash(u'Password incorrect, please try again.')
            return redirect(url_for('login'))
        elif check_password_hash(user.password, password):
            login_user(user)

            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, error=error, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    user = current_user
    requested_post = BlogPost.query.get(post_id)
    comment = CommentForm()
    print(requested_post.comments[5].comment_author.name)

    print(current_user)
    if comment.validate_on_submit():
        if current_user.is_anonymous:
            return redirect(url_for('login'))
        else:
            new_post = Comment(
                author_id=current_user.id,
                post_id=post_id,
                comment=comment.comment.data
                )
            db.session.add(new_post)
            db.session.commit()

            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", comment=comment, post=requested_post, logged_in=current_user.is_authenticated,
                           user=user)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    create_post = CreatePostForm()
    if create_post.validate_on_submit():
        new_post = BlogPost(
            title=create_post.title.data,
            subtitle=create_post.subtitle.data,
            body=create_post.body.data,
            img_url=create_post.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=create_post, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
