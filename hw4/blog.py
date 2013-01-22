import os
import re
import string
from string import letters

import webapp2
import jinja2
import hashlib
import random

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#hasing + salt
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

class Signup(BaseHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        Users = db.GqlQuery("select * from User where username = :1", username)
        if not Users.count() is 0:
        	params['error_username2'] = "That user already exists."
        	have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
        	hashingPassword = make_pw_hash(username,password)        	
        	u = User(username = username,password = hashingPassword,email = email)
        	u.put()
        	self.response.headers.add_header('Set-Cookie','userinfo=%s|%s' % (u.key().id(), hashingPassword.split(',')[0]))
        	self.redirect('/unit4/welcome')
        	#self.redirect('/unit4/welcome?username=' + username)

class Welcome(BaseHandler):
    def get(self):
        #username = self.request.get('username')
        userinfo = self.request.cookies.get('userinfo',0)
        if not userinfo:
        	self.redirect('/unit4/signup')
       	else:
	        userid = userinfo.split('|')[0]

	        key = db.Key.from_path('User',int(userid))
	        user = db.get(key)

	        if not user:
	        	self.redirect('/unit4/signup')
	        else:
		        if user.password.split(',')[0] == userinfo.split('|')[1]:
		        	self.render('welcome.html', username = user.username)
		        	#self.response.headers['Content-Type'] = 'text/plain'
		        	#self.write("%s, %s" %(user.password.split(',')[0], userinfo.split('|')[1]))
		        else:
		        	self.redirect('/unit4/signup')

class Logout(BaseHandler):
	def get(self):
		empty=''
		self.response.headers.add_header('Set-Cookie', 'userinfo= %s; path=/;' %empty)
		self.redirect('/unit4/signup')

	def post(self):
		pass


class Login(BaseHandler):
	def get(self):
		self.render("login-form.html")
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		users = db.GqlQuery("select * from User where username = :1", username)
		
		if users.count() == 1:
			for user in users:
				hashingPassword = make_pw_hash(username,password,user.password.split(',')[1])
				if(hashingPassword == user.password):
					cookievalue = str(user.key().id()) + '|' + user.password.split(',')[0]
					self.response.headers.add_header('Set-Cookie', str('userinfo=' + cookievalue))
					self.redirect('/unit4/welcome')

		else:
			self.render("login-form.html", invalid_login = 'invalid login')

			#self.response.headers['Content-Type'] = 'text/plain'
			#self.write("%s" % users.count())

app = webapp2.WSGIApplication([('/unit4/signup', Signup),
							   ('/unit4/login',Login),
							   ('/unit4/logout',Logout),
							   ('/unit4/welcome',Welcome)],
							   debug=True)