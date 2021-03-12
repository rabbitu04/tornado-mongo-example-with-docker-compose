import os

from bcrypt import hashpw, checkpw, gensalt
from datetime import datetime
from pymongo import MongoClient
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler
from uuid import uuid1

client = MongoClient('mongodb://testroot:testpass@db/testDB?authSource=admin')
db = client['testDB']


class HelloWorldHandler(RequestHandler):
    
    def get(self):
        print('')
        print('Hello world')
        return self.write('Hello World')


class RegisterHandler(RequestHandler):
    
    def get(self):
        self.render('register.html')
    
    def post(self):
        name = self.get_argument('name')
        email    = self.get_argument('email')
        password = self.get_argument('password')
        if db.users.find_one({'email': email}):
            self.write('Email "' + email + '" has been used.')
            return
        if email and password:
            db.users.insert_one({
                'name': name,
                'email'          : email,
                'hashed_password': hashpw(password.encode('utf-8'), gensalt()),
            })
            self.write('Register success.')
            return
        
        
class LoginHandler(RequestHandler):
    
    def get(self):
        self.render('login.html')
    
    def post(self):
        email    = self.get_argument('email')
        password = self.get_argument('password')
        if email and password:
            user = db.users.find_one({'email': email})
            if checkpw(password.encode('utf-8'), user['hashed_password']):
                session_id = str(uuid1())
                self.set_cookie('session_id', session_id)
                self.set_cookie('user', user['name'])
                db.sessions.delete_many({'email': email})
                db.sessions.insert_one({
                    'session_id': session_id,
                    'email'     : email,
                    'login_at'  : datetime.now(),
                })
                self.write('Login success.')
                return
        self.write('Login failed')
        return


class LogoutHandler(RequestHandler):
    
    def get(self):
        session_id = self.get_cookie('session_id')
        db.sessions.delete_many({'session_id': session_id})
        self.set_cookie('session_id', '')
        self.set_cookie('user', '')
        self.write('Bye.')


class BaseHandler(RequestHandler):
    
    def login_required(func):
        
        def wrapper(self, *args, **kwargs):
            session_id = self.get_cookie('session_id')
            print('*' * 5, 'CHECK IF LOGIN', '*' * 5)
            print('SESSION ID:', session_id)
            print()
            if db.sessions.find_one({'session_id': session_id}):
                return func(self, *args, **kwargs)
            self.redirect('/login')

        return wrapper
    
    @login_required 
    def get(self):
        self.write('Hi ' + self.get_cookie('user') + '<br>')
        self.write('This is index, login required.')
        

def make_app():
    
    print('-' * 10, 'APP START', '-' * 10)

    routers = [
        # Base
        (r'/', BaseHandler),
        (r'/hello-world', HelloWorldHandler),
        # Login
        (r'/login', LoginHandler),
        (r'/logout', LogoutHandler),
        (r'/register', RegisterHandler),
    ]

    settings = dict(
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        xsrf_cookies=True,
    )

    return Application(routers, **settings)
    
    
if __name__ == '__main__':
    app = make_app()
    app.listen(8080)
    IOLoop.current().start()
