import os
import os.path
from flask import Flask, request, redirect, url_for, render_template, session, send_from_directory, send_file
from werkzeug.utils import secure_filename
import DH
import pickle
import random

UPLOAD_FOLDER = './media/text-files/'
UPLOAD_KEY = './media/public-keys/'
ALLOWED_EXTENSIONS = set(['txt', 'jpg', 'png', 'pdf'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

'''
-----------------------------------------------------------
					PAGE REDIRECTS
-----------------------------------------------------------
'''
def post_upload_redirect():
	return render_template('post-upload.html')

@app.route('/register')
def call_page_register_user():
	return render_template('register.html')

@app.route('/home')
def back_home():
	return render_template('index.html')

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/upload-file')
def call_page_upload():
	return render_template('upload.html')
'''
-----------------------------------------------------------
				DOWNLOAD KEY-FILE
-----------------------------------------------------------
'''
@app.route('/public-key-directory/retrieve/key/<username>')
def download_public_key(username):
    for filename in os.listdir(UPLOAD_KEY):
        # Match either pattern:
        if filename.startswith(username + '-') or filename == username + '_diffie.pem':
            return send_file(
                os.path.join(UPLOAD_KEY, filename),
                as_attachment=True,
                attachment_filename='publicKey.pem'
            )
    return "Public key not found", 404

@app.route('/file-directory/retrieve/file/<filename>')
def download_file(filename):
	filepath = UPLOAD_FOLDER+filename
	if(os.path.isfile(filepath)):
		return send_file(filepath, attachment_filename='fileMessage-thrainSecurity.txt',as_attachment=True)
	else:
		return render_template('file-list.html',msg='An issue encountered, our team is working on that')

'''
-----------------------------------------------------------
		BUILD - DISPLAY FILE - KEY DIRECTORY
-----------------------------------------------------------
'''
# Build public key directory
@app.route('/public-key-directory/')
def downloads_pk():
    try:
        if os.path.isfile("./media/database/database_1.pickle"):
            with open("./media/database/database_1.pickle","rb") as f:
                username = pickle.load(f)
                if username:
                    return render_template('public-key-list.html',
                                       msg='',
                                       itr=0,
                                       length=len(username),
                                       directory=username)
        return render_template('public-key-list.html',
                           msg='Aww snap! No public key found in the database')
    except Exception as e:
        return "Error: %s" % str(e)

# Build file directory
@app.route('/file-directory/')
def download_f():
	for root,dirs,files in os.walk(UPLOAD_FOLDER):
		if(len(files) == 0):
			return render_template('file-list.html',msg='Aww snap! No file found in directory')
		else:
			return render_template('file-list.html',msg='',itr=0,length=len(files),list=files)

'''
-----------------------------------------------------------
				UPLOAD ENCRYPTED FILE
-----------------------------------------------------------
'''
# Update your upload_file route
@app.route('/data', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if file exists in request
        if 'file' not in request.files:
            return 'No file part in request', 400
            
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            return 'No file selected', 400
        
        # Check file extension
        if not allowed_file(file.filename):
            return 'Invalid file type. Only .txt files are allowed', 400
        
        # Ensure upload directory exists
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        # Secure the filename and save
        filename = secure_filename(file.filename)
        try:
            file.save(os.path.join(upload_folder, filename))
            return post_upload_redirect()
        except Exception as e:
            return 'Error saving file: %s' % str(e), 500
    
    return redirect(url_for('call_page_upload'))

'''
-----------------------------------------------------------
REGISTER UNIQUE USERNAME AND GENERATE PUBLIC KEY WITH FILE
-----------------------------------------------------------
'''
@app.route('/register-new-user', methods=['GET', 'POST'])
def register_user():
    # Load databases
    privatekeylist = []
    usernamelist = []
    try:
        with open("./media/database/database.pickle", "rb") as f:
            privatekeylist = pickle.load(f)
    except (IOError, pickle.UnpicklingError):
        privatekeylist = []
    
    try:
        with open("./media/database/database_1.pickle", "rb") as f:
            usernamelist = pickle.load(f)
    except (IOError, pickle.UnpicklingError):
        usernamelist = []

    # Validate
    username = request.form['username']
    if username in usernamelist:
        return render_template('register.html', name='Username already exists')

    # Generate keys
    privatekey = DH.generate_private_key(random.randint(1, 128) % 64)
    while str(privatekey) in privatekeylist:
        privatekey = DH.generate_private_key(random.randint(1, 128) % 64)

    # Update databases
    privatekeylist.append(str(privatekey))
    usernamelist.append(username)
    with open("./media/database/database.pickle", "wb") as f:
        pickle.dump(privatekeylist, f, protocol=2)  # protocol=2 for Py2 compatibility
    with open("./media/database/database_1.pickle", "wb") as f:
        pickle.dump(usernamelist, f, protocol=2)

    # Save public key
    if not os.path.exists(UPLOAD_KEY):
        os.makedirs(UPLOAD_KEY)
    filename = os.path.join(UPLOAD_KEY, 
                          "{}-{}{}-PublicKey.pem".format(
                              username,
                              request.form['last-name'].upper(),
                              request.form['first-name'].lower()))
    with open(filename, "w") as f:
        f.write(str(DH.generate_public_key(privatekey)))

    return render_template('key-display.html', privatekey=str(privatekey))


	
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)  