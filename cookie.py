import webapp2
import os
import jinja2
import hashlib
import hmac
import libs.bcrypt
SECRET = "thisisthebestsecretever"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def hash_str(s):
    return hmac.new(SECRET, s, hashlib.sha512).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(Handler):
    def get(self):
        # self.response.headers['Content-Type'] = 'text/plain'
        # visits = 0
        # visits_cookie_str = self.request.cookies.get('visits')
        # if visits_cookie_str:
        #     cookie_val = check_secure_val(visits_cookie_str)
        #     if cookie_val:
        #         visits = int(cookie_val)
        # visits += 1
        # new_cookie_val = make_secure_val(str(visits))
        # self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)

        # self.write("You've been here %s times!" % visits)
        password = "super ultra secrure password"
        hashed = libs.bcrypt.hashpw(password, libs.bcrypt.gensalt())

        # gensalt's log_rounds parameter determines the complexity.
        # The work factor is 2**log_rounds, and the default is 12
        hashed = libs.bcrypt.hashpw(password, libs.bcrypt.gensalt())

        # Check that an unencrypted password matches one that has
        # previously been hashed
        if libs.bcrypt.hashpw(password, hashed) == hashed:
                self.write("It matches")
        else:
                self.write("It does not match")

app = webapp2.WSGIApplication([
    ('/', MainPage)
], debug=True)
