from flask import Flask, render_template, send_file, request, redirect, url_for, session, jsonify, abort
from flask_socketio import SocketIO, emit
from sqlalchemy import create_engine, Column, Integer, Text, text, String
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.future import select
from base64 import b64decode as b64d
import json
import os
import re
import hashlib
import base64
from functools import wraps
from dotenv import load_dotenv
import traceback

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(32))
socketio = SocketIO(app)

SITE_PASSWORD = hashlib.sha256(os.environ['SITE_PASSWORD'].encode()).hexdigest()
EDITOR_PASSWORD = hashlib.sha256(os.environ['EDITOR_PASSWORD'].encode()).hexdigest()
EDITABLE_DIRECTORY = os.environ.get('EDITABLE_DIRECTORY', './rules')
os.makedirs(EDITABLE_DIRECTORY, exist_ok=True)
DB_URL = os.environ['DB_URL']
WEB_PORT = int(os.environ.get('WEB_PORT', 8080))
services = json.load(open('services.json', 'r'))

MAX_PORT_DIFFERENCE = 10
PORT_DIFFERENCE = 3


engine = create_engine(DB_URL, echo=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Streams(Base):
    __tablename__ = 'streams'
    id = Column(Integer, primary_key=True, autoincrement=True)
    stream = Column(LONGTEXT, nullable=False)
    service_name = Column(String(255), nullable=True)
    remote_addr = Column(String(255), nullable=True)

def insert_stream(stream, service_name, remote_addr):
    session = SessionLocal()
    try:
        new_stream = Streams(stream=stream, service_name=service_name, remote_addr=remote_addr)
        session.add(new_stream)
        session.commit()
        return new_stream.id
    finally:
        session.close()

def load_patterns(service_name):
    patterns = []

    for filename in os.listdir(EDITABLE_DIRECTORY):
        if not filename.endswith('.json'):
            continue

        try:
            with open(os.path.join(EDITABLE_DIRECTORY, filename), 'r') as f:
                pattern = json.load(f)

                required_keys = ['pattern', 'flag', 'std', 'active', 'action', 'service']
                if not all(key in pattern for key in required_keys):
                    print(f"Invalid pattern format in {filename}")
                    continue

                if not pattern.get('active', False):
                    continue

                if pattern['service'] == 'ALL':
                    pass
                # elif pattern['service'] == 'KERNEL':
                #     if service_name is not None and service_name != '':
                #         if services[service_name]['is_http']:
                #             print(f"Skipping KERNEL pattern for HTTP service {service_name}")
                #             continue
                elif pattern['service'] != service_name:
                    continue 

                try:
                    pattern['compiled'] = re.compile(pattern['pattern'])
                    patterns.append(pattern)
                except re.error as e:
                    print(f"Invalid regex in {filename}: {e}")

        except json.JSONDecodeError as e:
            print(f"Invalid JSON in {filename}: {e}")
        except Exception as e:
            print(f"Error loading pattern {filename}: {e}")

    return patterns


def site_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('site_logged_in'):
            return redirect(url_for('site_login'))
        return f(*args, **kwargs)
    return decorated_function

def editor_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('editor_logged_in'):
            return redirect(url_for('editor_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def site_login():
    if request.method == 'POST':
        if SITE_PASSWORD == request.form.get('password'):
            session['site_logged_in'] = True
            return redirect(url_for('get_streams'))
        return render_template('login.html', error='Неверный пароль сайта', login_type='site')
    return render_template('login.html', login_type='site')

@app.route('/editor-login', methods=['GET', 'POST'])
def editor_login():
    if request.method == 'POST':
        if EDITOR_PASSWORD == request.form.get('password'):
            session['editor_logged_in'] = True
            return redirect(url_for('editor'))
        return render_template('login.html', error='Неверный пароль редактора', login_type='editor')
    return render_template('login.html', login_type='editor')

@app.route('/logout')
def logout():
    session.pop('site_logged_in', None)
    session.pop('editor_logged_in', None)
    return redirect(url_for('site_login'))


def get_flags_in_stream(stream, service_name, should_check=False):
    patterns = load_patterns(service_name)  # Загружаем актуальные паттерны
    parsed_data = json.loads(b64d(stream).decode())
    flags = {}
    marks = {}

    if should_check:
        flags[f'service: {service_name}'], marks[f'service: {service_name}'] = None, None

    for item in parsed_data:
        std, length, base64_str = item
        decoded_str = str(b64d(base64_str))[2:-1]

        try:
            if 'HTTP' in decoded_str.split('\\n')[0] and std == 0:
                flags[decoded_str.split('\\n')[0].split('HTTP')[0]] = None

            if 'HTTP' in decoded_str.split('\\n')[0] and std == 1:
                flags[decoded_str.split('\\n')[0].split(' ')[1]] = None
        except:
            pass

        for pattern in patterns:
            if not pattern['active']:
                continue

            if pattern['compiled'].search(decoded_str):
                if pattern['std'] is None or pattern['std'] == std:
                    flags[pattern['flag']] = None
                    if pattern['action'] == 'mark':
                        marks[pattern['flag']] = None

        try:
            b64d(base64_str).decode()
        except:
            flags['non_printable'] = None

    return {
        'flags': list(flags.keys()),
        'marks': list(marks.keys())
    }

@app.route('/')
@site_login_required
def index():
    with open('services.json', 'r') as file:
        services = json.load(file)
    return render_template('services.html', services=services)

@app.route('/streams', methods=['GET']) # добавить сюда переключение по номеру страницы (500 стримов на одну страницу +-) 
@site_login_required
def get_streams():
    session_db = SessionLocal()
    try:
        service_name: str
        streams_data = []
        if not request.args.get('name'):
            result = session_db.query(Streams.id, Streams.stream, Streams.service_name) \
                            .order_by(Streams.id.desc()) \
                            .limit(500)
            service_name = None
        else:
            service_name = request.args.get('name')
            result = session_db.query(Streams.id, Streams.stream) \
                            .filter(Streams.service_name == service_name) \
                            .order_by(Streams.id.desc()) \
                            .limit(500)

        streams = result.all()

        streams_data = []
        for row in streams:
            if not request.args.get('name'):
                id, data, service_name = row
            else:
                id, data = row
            try:
                result = get_flags_in_stream(data, service_name)
                streams_data.append({
                    "id": id,
                    "flags": result['flags'],
                    "marks": result['marks']
                })
            except Exception as e:
                streams_data.append({
                    "id": id,
                    "flags": [],
                    "marks": []
                })

        return render_template('streams.html', streams=streams_data)
    finally:
        session_db.close()

@app.route('/streams/<int:id>', methods=['GET'])
@site_login_required
def get_stream_by_id(id):
    session_db = SessionLocal()
    try:
        result = session_db.execute(select(Streams).filter_by(id=id))
        stream_info = result.scalar_one_or_none()
        if stream_info:
            return render_template('stream.html', data=stream_info.stream)
        return "Stream not found", 404
    finally:
        session_db.close()

@app.route('/should_check')
@site_login_required
def checker_or_sploit():
    session_db = SessionLocal()
    try:
        result = session_db.query(Streams.id, Streams.stream, Streams.service_name) \
                            .order_by(Streams.id.desc()) \
                            .limit(3000)
        streams = result.all()

        streams_data = []
        for row in streams:
            id, data, service_name = row
            try:
                result = get_flags_in_stream(data, service_name, True)
                streams_data.append({
                    "id": id,
                    "flags": result['flags'],
                    "marks": result['marks']
                })
            except Exception as e:
                streams_data.append({
                    "id": id,
                    "flags": [],
                    "marks": []
                })
    except:
        return "Database error", 500
    return render_template('streams.html', streams=[item for item in streams_data if 'flag' in item['flags']])


def get_json_files():
    return [f for f in os.listdir(EDITABLE_DIRECTORY) 
            if f.endswith('.json') and os.path.isfile(os.path.join(EDITABLE_DIRECTORY, f))]

def valid_filename(filename):
    return (filename and filename.endswith('.json') 
            and not '/' in filename and not '\\' in filename)

@app.route('/editor')
@editor_login_required
def editor():
    return render_template('editor.html', files=get_json_files())

@app.route('/api/files')
@editor_login_required
def api_files():
    return jsonify({'files': get_json_files()})

@app.route('/api/file', methods=['GET'])
@editor_login_required
def api_get_file():
    filename = request.args.get('filename')
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    filepath = os.path.join(EDITABLE_DIRECTORY, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        with open(filepath, 'r') as f:
            return jsonify({'content': f.read()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/new', methods=['POST'])
@editor_login_required
def api_create_file():
    filename = request.json.get('filename')
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    filepath = os.path.join(EDITABLE_DIRECTORY, filename)
    if os.path.exists(filepath):
        return jsonify({'error': 'File already exists'}), 400
    
    # Шаблон нового файла
    new_file_content = {
        "service": "",
        "pattern": "",
        "flag": "",
        "std": None,
        "active": True,
        "action": "mark"
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(new_file_content, f, indent=2)
        return jsonify({'success': True, 'filename': filename})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file', methods=['POST'])
@editor_login_required
def api_save_file():
    data = request.json
    filename = data.get('filename')
    content = data.get('content')
    
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    try:
        # Валидация JSON и обязательных полей
        pattern_data = json.loads(content)
        required_fields = ['pattern', 'flag', 'std', 'active', 'action']
        if not all(field in pattern_data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        if pattern_data['action'] not in ['mark', 'ban']:
            return jsonify({'error': 'Invalid action type'}), 400
        re.compile(pattern_data['pattern'])  # Проверка regex
    except re.error as e:
        return jsonify({'error': f'Invalid regex: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Invalid JSON: {str(e)}'}), 400
    
    try:
        with open(os.path.join(EDITABLE_DIRECTORY, filename), 'w') as f:
            f.write(content)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file', methods=['DELETE'])
@editor_login_required
def api_delete_file():
    filename = request.json.get('filename')
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    filepath = os.path.join(EDITABLE_DIRECTORY, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        os.remove(filepath)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def http_to_python_requests(data):
    headers, data = data.split('\n\n')

    result_data = 'headers = {\n'
    for header in headers.split('\n')[1:]:
        if header.split(':')[0] == 'Host':
            result_data += f"\t'{header.split(':')[0]}': f'{{sys.argv[1]}}:{header.split(':')[2]}',\n"
            continue
        if len(header.split(':')) > 2:
            result_data += f"\t'{header.split(':')[0]}': '{':'.join(header.split(':')[1:])}',\n"
        else:
            result_data += f"\t'{header.split(':')[0]}': '{header.split(': ')[1]}',\n"
    result_data += '}\n'

    if '=' in data:
        result_data += 'data = {\n'
        for param in data.split('&'):
            result_data += f"\t'{param.split('=')[0]}': '{param.split('=')[1]}',\n"
        result_data += '}\n'

    method = headers.split('\n')[0].split(' ')[0]
    route = headers.split('\n')[0].split(' ')[1]

    if '=' in data:
        match method:
            case 'GET':
                result_data += f'response = session.get(base_url + "{route}", headers=headers, data=data)\n'
            case 'POST':
                result_data += f'response = session.post(base_url + "{route}", headers=headers, data=data)\n'
            case 'DELETE':
                result_data += f'response = session.delete(base_url + "{route}", headers=headers, data=data)\n'
            case 'PUT':
                result_data += f'response = session.put(base_url + "{route}", headers=headers, data=data)\n'
    else:
        match method:
            case 'GET':
                result_data += f'response = session.get(base_url + "{route}", headers=headers)\n'
            case 'POST':
                result_data += f'response = session.post(base_url + "{route}", headers=headers)\n'
            case 'DELETE':
                result_data += f'response = session.delete(base_url + "{route}", headers=headers)\n'
            case 'PUT':
                result_data += f'response = session.put(base_url + "{route}", headers=headers)\n'

    return result_data

def process_http_export_data(queries):
    sploit_data = 'import requests\nimport sys\n\n'
    sploit_data += 'session = requests.Session()\n'
    sploit_data += f"base_url = f'http://{{sys.argv[1]}}:{services[queries[0].service_name]['in_port']}'\n\n"

    port_diff = int(queries[0].remote_addr.split(':')[1]) - int(queries[1].remote_addr.split(':')[1])
    if port_diff > MAX_PORT_DIFFERENCE:
        decoded_str = json.loads(b64d(queries[0].stream).decode())
        decoded_str = str(b64d(decoded_str[0][2]))[2:-1].replace('\\r\\n', '\n')
        sploit_data += http_to_python_requests(decoded_str)
        sploit_data += 'print(response.text, flush=True)'
        return sploit_data
    
    export_data = [queries[0]]
    for i in range(len(queries) - 1):
        tmp_diff = int(queries[i].remote_addr.split(':')[1]) - int(queries[i + 1].remote_addr.split(':')[1])
        if tmp_diff - PORT_DIFFERENCE <= port_diff:
            export_data.append(queries[i + 1])
        else:
            break
    
    for item in export_data[::-1]:
        sploit_data += '\n'
        decoded_str = json.loads(b64d(item.stream).decode())
        decoded_str = str(b64d(decoded_str[0][2]))[2:-1].replace('\\r\\n', '\n')
        sploit_data += http_to_python_requests(decoded_str)
        sploit_data += '\n'
    sploit_data += 'print(response.text, flush=True)'
    return sploit_data

def should_print(text, is_http=False):
    pattern_flag = r'[A-Z0-9]{31}='
    pattern_addr = r'0x[a-f0-9]+'

    non_printable = False
    for i in text:
        if (i < 0x20 and (i < 0x07 or i > 0x0d)) or i > 0x7e:
            non_printable = True
            break

    if not is_http:
        return non_printable or re.search(pattern_flag, text.decode()) or re.search(pattern_addr, text.decode())
    else:
        return non_printable or re.search(pattern_flag, text.decode())

def generate_export_data(id):
    session_db = SessionLocal()
    try:
        result = session_db.execute(select(Streams).filter_by(id=id))
        if not (stream_info := result.scalar_one_or_none()):
            raise Exception('Stream not found')
        
        process = json.loads(b64d(stream_info.stream).decode())
        if len(process) == 1 and process[0][0] == 1:
            raise Exception('Nothing to do')
        
        if re.search(r'[A-Z]+ /[^ ]* HTTP/', str(b64d(process[0][2]))[2:-1]) and process[0][0] == 0:
            # return file_data + f"io.send(b'{str(b64d(process[0][2]))[2:-1]}')\n\nio.interactive()"
            queries = session_db.query(Streams).filter(
                Streams.service_name == stream_info.service_name,
                Streams.remote_addr.like(f"%{stream_info.remote_addr.split(':')[0]}:%"),
                Streams.id <= stream_info.id
            ).order_by(Streams.id.desc()).limit(10).all()
            return process_http_export_data(queries)

        file_data = 'import sys\nfrom pwn import *\n\n'
        file_data += f"io = remote(sys.argv[1], {services[stream_info.service_name]['in_port']})\n# io = process(['./binary_name'])\n\n"

        if len(process) == 1 and process[0][0] == 0:
            return file_data + f"io.send(b'{str(b64d(process[0][2]))[2:-1]}')\n\nio.interactive()"

        skip = False
        for i in range(len(process)):
            if skip:
                skip = False
                continue
                
            if process[i][0] == 0:
                if i == 0:
                    file_data += f"io.send(b'{str(b64d(process[i][2]))[2:-1]}')\n"
                else:
                    prev_data = str(b64d(process[i-1][2]))[2:-1]
                    curr_data = str(b64d(process[i][2]))[2:-1]
                    suffix = prev_data[-10:] if process[i-1][1] > 10 else prev_data
                    file_data += f"io.sendafter(b'{suffix}', b'{curr_data}')\n"
            else:
                if should_print(b64d(process[i][2])):
                    file_data += 'print(io.recv(), flush=True)\n'
                    if i+1 < len(process) and process[i+1][0] == 0:
                        file_data += f"io.send(b'{str(b64d(process[i+1][2]))[2:-1]}')\n"
                        skip = True

        return file_data + '\nio.interactive()'
    except Exception as e:
        print(f'Export error: {str(e)}')
        traceback.print_exc() 
    finally:
        session_db.close()

@app.route('/export_sploit/<int:id>')
@site_login_required
def export_text(id):
    try:
        data = generate_export_data(id)
        filename = f"splo_{id}.py"
        filepath = os.path.join("/tmp", filename)

        with open(filepath, "w", encoding="utf-8") as file:
            file.write(data)

        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype="text/plain"
        )
    except Exception as e:
        return f"Ошибка при экспорте: {str(e)}", 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

@app.route('/api/banned-patterns', methods=['GET'])
def get_banned_patterns():
    banned_patterns = []

    service_name = request.args.get('service_name')
    
    for filename in os.listdir(EDITABLE_DIRECTORY):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(EDITABLE_DIRECTORY, filename), 'r') as f:
                    pattern = json.load(f)
                    # if service_name is None or service_name != pattern.get('service'):
                    #     continue
                    if pattern.get('action') == 'ban' and pattern.get('active', False) and (service_name == pattern.get('service') or pattern.get('service') == 'ALL'):
                        banned_patterns.append(pattern)
            except Exception as e:
                print(f"Error loading pattern {filename}: {e}")
                continue
    
    return jsonify({
        'count': len(banned_patterns),
        'banned_patterns': banned_patterns
    })

@app.route('/api/services', methods=['GET'])
def get_services():
    return jsonify(services)
    
@app.route('/api/new_stream', methods=['POST'])
def add_new_stream_to_db():
    try:
        data = request.get_json()
        if data is None:
            return 'Invalid JSON', 400
        
        stream = []
        
        if 'is_http' not in data:
            return 'Missing request data', 400
            
        if data['is_http']:
            req = data['request']
            stream.append([
                req.get('std'),
                req.get('dataLen'),
                req.get('data')
            ])
            
            if 'response' in data and data['response'] is not None:
                resp = data['response']
                stream.append([
                    resp.get('std'),
                    resp.get('dataLen'),
                    resp.get('data')
                ])
        else:
            for item in data['stream']:
                stream.append([
                    item.get('std'),
                    item.get('dataLen'),
                    item.get('data')
                ])

        stream_str = json.dumps(stream)
        stream_to_db = base64.b64encode(stream_str.encode('utf-8')).decode('utf-8')
        stream_id = insert_stream(stream_to_db, data['service_name'], data['remote_addr'])

        stream = {
            'id': stream_id,
            'service': data['service_name'],
            'flags': get_flags_in_stream(stream_to_db, data['service_name'])['flags']
        }
        socketio.emit('new_stream', stream)
        
    except json.JSONDecodeError:
        return 'Invalid JSON format', 400
    except KeyError as e:
        return f'Missing key: {str(e)}', 400
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return 'Internal server error', 500
    return 'OK', 200


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    app.run(host='0.0.0.0', port=WEB_PORT)