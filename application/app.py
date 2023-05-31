from flask import Flask, render_template, request, url_for, redirect, flash
from flask import session, request, jsonify
from forms import UploadForm

# For executing sh files
import subprocess
from subprocess import Popen, PIPE
import asyncio
import sys
import magic
import threading
from threading import Lock
from threading import Thread, Event
from flask_socketio import SocketIO, emit, disconnect, send
import eventlet

from time import sleep

# For looking sh files
import os
from os import listdir
from os.path import isfile, join
from werkzeug.utils import secure_filename
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(app)

# App routes
@app.route("/", methods=["GET"], endpoint="home")
def home_page():
    return render_template("/home.html")

@app.route("/attackdashboard", methods = ['POST', 'GET'])
def attack_dashboard():
    return render_template('attackdashboard.html')

def run_script(queue_in, fileName, event):
    command = './scripts/' + fileName
    
    if "ssh" in command:
        try:
            with subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  shell=True, encoding='utf-8', errors='replace') as process:
                process.kill()

            testSSHCommand = "sshpass -p 'Student12345@' ssh -o ConnectTimeout=5 student@172.16.2.223"
            with subprocess.Popen([testSSHCommand], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  shell=True, encoding='utf-8', errors='replace') as testSSHProcess:
                output, _ = testSSHProcess.communicate()

                if "Connection timed out" in output:
                    queue_in.put(output)
                    queue_in.put("Connection timed out. Access to Smart Meter PC on port 22 has been blocked")
                    queue_in.put("Ok.")
        except subprocess.CalledProcessError as e:
            queue_in.put(f"Error: {e}")
            queue_in.put("Fail.")

    else:
        try:
            with subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  shell=True, encoding='utf-8', errors='replace') as process:
                output, _ = process.communicate()

                if "timed out" in output or "not recognized" in output or "permission denied" in output or "cannot find the path specified" in output:
                    queue_in.put(output)
                    queue_in.put("Fail.")
                else:
                    queue_in.put(output.strip())
                    queue_in.put("Ok.")
        except subprocess.CalledProcessError as e:
            queue_in.put(f"Error: {e}")
            queue_in.put("Fail.")

    event.set()

def emit_script(queue_in, event):

    # While loop to constantly check if: 
    while True:
        """
        # if the queue is empty and if its not empty,
        # consume data from the queue and emit the line to client browser 
        """
        if not queue_in.empty():
            line = queue_in.get()
            eventlet.sleep(0)
            # Emit to browser client where socket event listener is socket.on(scriptoutput)
            socketio.emit('scriptoutput', {'number': str(line)}, namespace='/test')
        """
        # if event flag has been set by run_script thread
        # break out of while loop 
        """ 
        if event.is_set():
            break

    return


@socketio.on('connect', namespace='/test')
def trigger_attack():

    fileName = request.args.get('file')

    if not fileName.endswith(".sh"):
        socketio.emit('scriptoutput', {'number': str("File selected is not an sh file. Please try again")}, namespace='/test')
        socketio.emit('scriptoutput', {'number': str("Fail.")}, namespace='/test')
        return

    # Create Queue for the 2 threads to produce into and consume from
    attackIOQueue = eventlet.Queue()
    # Create event for subprocess to set event flags
    event = Event()
    
    # Create one thread to run subprocess to execute sh files 
    t = socketio.start_background_task(run_script, attackIOQueue, fileName, event)

    # Create another thread to emit output of subprocess to client browser
    t2 = socketio.start_background_task(emit_script, attackIOQueue, event)

    # Stop the thread once sub-process in emit_script is completed and event.set()
    t.join()
    t2.join()

    return

#===============================================Get Various Statuses=================================================#
#Thread to run subprocess to get status of FW, Win Defender and Kepserver

def get_statuses(queue_in, event):
    fileName = "getallstatus.sh"
    script_path = os.path.join("scripts", fileName)
    command = f"./{script_path}"

    try:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, encoding='utf-8', errors='replace')
        output_string = process.stdout
    except subprocess.CalledProcessError as e:
        queue_in.put("Error occurred: " + str(e))
        return

    output_stringlist = []
    for realtime_output in output_string.splitlines():
        if "Connection timed out" in realtime_output:
            queue_in.put("Fail.")
            break
        if realtime_output:
            realtime_output = realtime_output.replace('-', '').replace(':', '')
            output_stringlist.append(realtime_output.strip())

    if output_stringlist:
        output = firewall_status(output_stringlist)
        queue_in.put(output)
        queue_in.put("Ok.")

    event.wait(timeout=3)
    return

def emit_statuses(queue_in, event):
    while True:
        if not queue_in.empty():
            line = queue_in.get()
            # Emit to browser client where socket event listener is socket.on(statusoutput)
            socketio.emit('statusoutput', {'number': line}, namespace='/statuses')
        if event.is_set():
            break

    return


def firewall_status(stringlist):
    # Remove empty string from list
    stringlist = list(filter(None, stringlist))
    # Remove "OK." from stringlist to make array have even values as stringlist array has odd number of values
    stringlist.remove("Ok.")
    """
    # Lower case all items in stringlist array
    # as well as unwanted values such as state and <spaces>
    """
    stringlist = [line.lower() for line in stringlist]
    stringlist = [line.replace('state', ' ') for line in stringlist]
    stringlist = [line.replace(' ', '') for line in stringlist]

    # Convert values in stringlist array to dictionary with key-value pairs
    it = iter(stringlist)
    res_dct = dict(zip(it, it))  

    return res_dct

# Namespace to get status of FW, Win Defender, and Kepserver
@socketio.on('connect', namespace='/statuses')
def trigger_status_retrieval():

    # Create event for subprocess to set event flags
    event = threading.Event()
    # Create Queue for threads to produce into and consume from
    statusIOQueue = eventlet.Queue()

    # Create one thread to run subprocess to retrieve various statuses of remote host
    t3 = socketio.start_background_task(get_statuses, statusIOQueue, event)

    # Create another thread to emit output of subprocess to client browser
    t4 = socketio.start_background_task(emit_statuses, statusIOQueue, event)

    # Stop the threads once the subprocess in emit_statuses is completed and event.set()
    t3.join()
    t4.join()

    return


# ==================Route to get .sh files for user to run in attack dashboard===============================================#
@app.route("/getshfiles", methods=["GET"])
def get_sh_files():
    listOfshFiles = get_list_of_sh_files_dict()
    return listOfshFiles

def get_list_of_sh_files_dict():
    existing_dict = {}
    scriptDirectory = os.path.join(".", "scripts")
    
    for file in os.listdir(scriptDirectory):
        if file.endswith(".sh"):
            filePath = os.path.join(scriptDirectory, file)
            
            with open(filePath, "r") as f:
                lines = [line.strip().lstrip("#") for line in f.readlines() if line.startswith(("Description:", "Tag:"))]
            
            existing_dict[file] = lines
    
    return existing_dict

# ===========================================================================================================================#
# This route is responsible for handling .exe and .sh file uploads to the local filesystem
@app.route('/uploadfile', methods=['GET', 'POST'])
@csrf_protect
def file_upload():
    form = UploadForm()

    if form.validate_on_submit(): 
        f = form.upload.data
        filename = secure_filename(f.filename)
        file_path = ''

        # Validate file type
        file_type = magic.from_buffer(f.stream.read(1024), mime=True)
        if file_type == 'application/x-dosexec':
            file_path = os.path.join(app.config['EXECUTABLES_PATH'], filename)
        elif file_type == 'text/x-shellscript':
            file_path = os.path.join(app.config['SCRIPTS_PATH'], filename)
        else:
            return jsonify({'message': 'Invalid file type. Only .exe and .sh files are allowed.'}), 400

        try:
            f.save(file_path)
            return jsonify({'message': 'File has been uploaded successfully.'}), 200
        except (FileNotFoundError, PermissionError, IOError):
            return jsonify({'message': 'Failed to upload the file.'}), 500

    return render_template('uploadfile.html', form=form)


# =====================================File Upload============================================================================ #
# Route is responsible for getting a list of .exe files uploaded to the local file system 
# and return it to uploadfile.html page on page load for Pen-tester to select
@app.route("/getexefiles", methods=["GET"])
def get_exe_files():
	listOfexeFiles = get_list_of_exe_files()
	return listOfexeFiles

def get_list_of_exe_files():
    existing_dict = {}
    executablesDirectory = './executables/'
    for file in os.listdir(executablesDirectory):
        if file.endswith(".exe"):
            existing_dict[file] = []
    return existing_dict

# Route is responsible for uploadig .exe files selected to the Smart Meter PC remotely
@app.route('/remotefileupload', methods=['GET', 'POST'])
def remote_file_upload():
    if request.method == "POST":
        select = request.form.get('exe-select')
        fileDirectory = request.form.get('file-directory')

        if not select.endswith(".exe"):
            flash_message = {'message': 'File selected does not have the .exe extension.', 'status': 'danger'}
            return redirect(url_for('file_upload', flash_message=flash_message))

        fullFileName = os.path.join('./executables/', select)

        if fileDirectory:
            # Strip any right trailing / or \ in the directory name
            fileDirectory = fileDirectory.rstrip("\\/")
            # Append " and " to the directory name string for the scp command
            fileDirectory = '"' + fileDirectory.strip() + '"'
            command = f'sshpass -p "Student12345@" scp -o ConnectTimeout=5 {fullFileName} student@172.16.2.223:{fileDirectory}'
        else:
            # If no specific file directory is provided, use the default directory
            command = f'sshpass -p "Student12345@" scp -o ConnectTimeout=5 {fullFileName} student@172.16.2.223:"C:\\Users\\student\\Desktop\\SharedFolder"'

        try:
            subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
            flash_message = {'message': 'File successfully uploaded to the remote host.', 'status': 'success'}
        except subprocess.CalledProcessError as e:
            if "No such file or directory" in e.output:
                flash_message = {'message': 'No such file or directory.', 'status': 'danger'}
            elif "Connection timed out" in e.output:
                flash_message = {'message': 'Unable to connect to the remote host. Connection timed out.', 'status': 'danger'}
            else:
                flash_message = {'message': 'An error occurred during the file transfer.', 'status': 'danger'}

        return redirect(url_for('file_upload', flash_message=flash_message))

    return redirect(url_for('file_upload'))


#=========================================File Download===============================================#

@app.route('/remotefiledownload', methods=['GET', 'POST'])
def remote_file_download():
    if request.method == "POST":
        remoteFileDirectory = request.form.get('remote-file-directory').strip().rstrip("\\/")
        localFileDirectory = request.form.get('local-file-directory').strip().rstrip("\\/")
        
        if remoteFileDirectory and localFileDirectory:
            command = f'sshpass -p "Student12345@" scp -o ConnectTimeout=5 -r student@172.16.2.223:"{remoteFileDirectory}" {localFileDirectory}'
        elif remoteFileDirectory:
            command = f'sshpass -p "Student12345@" scp -o ConnectTimeout=5 -r student@172.16.2.223:"{remoteFileDirectory}" /root/testdownload'
        elif localFileDirectory:
            command = f'sshpass -p "Student12345@" scp -o ConnectTimeout=5 -r student@172.16.2.223:"C:\\Users\\Student\\Documents\\AttackFolder" {localFileDirectory}'
        else:
            command = f'sshpass -p "Student12345@" scp -o ConnectTimeout=5 -r student@172.16.2.223:"C:\\Users\\Student\\Documents\\AttackFolder" /root/testdownload'
        
        try:
            subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
            flash_message = {'message': 'Files have been successfully copied to the local folder.', 'status': 'success'}
        except subprocess.CalledProcessError as e:
            if "No such file or directory" in e.output:
                flash_message = {'message': 'No such file or directory on the remote host.', 'status': 'danger'}
            elif "Connection timed out" in e.output:
                flash_message = {'message': 'Unable to connect to the remote host. Connection timed out.', 'status': 'danger'}
            else:
                flash_message = {'message': 'An error occurred during the file transfer.', 'status': 'danger'}
        
        return render_template('remotefiledownload.html', flash_message=flash_message)
    
    return render_template('remotefiledownload.html')


if __name__ == '__main__':
    eventlet.monkey_patch()
    socketio.run(app)
