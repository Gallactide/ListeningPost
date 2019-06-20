import yaml, json
import socket, os, subprocess, sys, platform, ssl, datetime, time

class InvalidParameter(Exception): pass

class Check:
	status = None
	name = None
	custom_content = None
	def __init__(self,name,*args,**kwargs):
		self.init(*args, **kwargs)
		if name:
			self.name = name
		else:
			self.name = self._gen_name()

	def init(self): pass
	def _gen_name(self): return "[ Unspecified ]"
	def run(self, *args, **kwargs):
		self.status = self._check()
	def print_status(self, offset=5):
		out = "[#] Check for {}:{}{}".format(self.name, "{}","PASS" if self.status else "FAIL")
		width = get_tty_size()[1]-offset-len(out)
		print(out.format(" "*(width)))

class FileCheck(Check):
	type_id = "Files"
	min = None
	max = None
	path = None
	def init(self, path, smin=None, smax=None):
		try:
			self.path = os.path.expanduser(path)
		except:
			self.path = path
		self.min = smin
		self.max = smax
	def _gen_name(self):
		return "File at '{}' {}{}{}".format(self.path, "min:"+str(self.min) if self.min!=None else "", ", " if (self.min!=None and self.max!=None) else "", "max:"+str(self.max) if self.max!=None else "")
	def _check(self):
		state = os.path.exists(self.path) and (not self.max or os.stat(self.path).st_size<=self.max) and (not self.min or self.min<=os.stat(self.path).st_size)
		return state

class ProcessCheck(Check):
	type_id = "Processes"
	def _gen_name(self): return "Process '{}'".format(self.p_name)
	def _check(self):
		return bool(len(subprocess.check_output(["ps aux | grep {}".format(self.p_name)], shell=True).decode().split("\n")[2:-1]))
	def init(self, p_name, pid=None):
		self.p_name = p_name
		self.pid = pid

class ServiceCheck(Check):
	type_id = "Services"
	def _gen_name(self): return "Service '{}'".format(self.p_name)
	def _check(self):
		try:
			return bool(subprocess.check_output(["sudo service {} status | grep Active".format(self.p_name)], shell=True, stderr=subprocess.DEVNULL).decode()[11:17]=="active")
		except:
			return False
	def init(self, p_name):
		self.p_name = p_name

class CheckSocket(Check):
	type_id = "Networking"
	port = None
	proto = None
	def init(self, p, pr):
		self.port = p
		self.proto = pr
	def _gen_name(self): return "Socket Listening on {} ({})".format(self.port, self.proto.upper())
	def _check(self, objects):
		for i in objects:
			if i==self.port and objects[i][0]==self.proto.upper():
				return True
		return False
	def run(self, objects):
		self.status = self._check(objects)

class CheckSocketRange(CheckSocket):
	type_id = "Networking"
	def _gen_name(self): return "Sockets Listening on {}-{} ({})".format(self.port[0], self.port[1], self.proto.upper())
	def _check(self, objects):
		for r in range(self.port[0], self.port[1]+1):
			if r not in objects:
				return False
		return True

class CertificateCheck(Check):
	_months = ["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"]
	type_id = "SSL Certificates"
	cert_path = None
	err = None
	def init(self, path):
		self.cert_path = path
		try:
			self.cert = ssl._ssl._test_decode_cert(self.cert_path)
		except Exception as e:
			self.cert = {"subject":[[[None, path+" "+str(e)]]]}
			self.err = e
	def _gen_name(self): return self.cert["subject"][0][0][1]
	def _is_valid(self):
		x = datetime.datetime.now()
		ts = self.cert["notAfter"].split()[:-1]
		ts[0] = self._months.index(ts[0].lower())+1
		decoded_ts = ts[2].split(":")
		#date check
		expires_on = datetime.datetime(int(ts[3]), ts[0], int(ts[1]), int(decoded_ts[0]),int(decoded_ts[1]),int(decoded_ts[2]))
		t_diff = expires_on-x
		return bool(t_diff.total_seconds()>0)
	def _check(self):
		try:
			self.cert = ssl._ssl._test_decode_cert(self.cert_path)
			return self._is_valid()
		except:
			return False

class AptUpdateCheck(Check):
	type_id = "Available Updates"
	check_interval = 120 #seconds
	last_state = None
	def init(self, security_only=False):
		self.last_check = time.time()-self.check_interval-1
		self.security_only = security_only
	def _gen_name(self): return "Security Updates" if self.security_only else "Available Updates"
	def _check(self):
		if (time.time()-self.last_check)>self.check_interval:
			self.last_check = time.time()
			self.last_state = subprocess.check_output(["/usr/lib/update-notifier/apt-check 2>&1"], shell=True).decode().split(";")
		return int(self.last_state[int(self.security_only)])

class DirectoryContentCheck(Check):
	def init(self, path):
		self.type_id = "Directory '{}' Content".format(path)
		self.path = path
	def _gen_name(self): return self.path
	def _check(self):
		t = os.listdir(self.path)
		self.custom_content = dict(zip(t, [True for i in range(len(t))]))

# Configuration
def get_parameters(path):
	with open(path) as cf:
		config = yaml.load(cf.read())
	if "listening" in config:
		for i in config["listening"]:
			o = {"ranges":[], "ports":[]}
			for k in config["listening"][i]:
				name = None
				j = k
				if type(k)==dict:
					j = list(k.keys())[0]
					name = k[j]
				if type(j)!=int and "-" in j:
					o["ranges"].append(tuple([name]+[int(k) for k in j.split("-")]))
				else:
					o["ports"].append((name, j))
			config["listening"][i]=o
	if "files" in config:
		out_d = {}
		for i in config["files"]:
			if type(i)!=dict:
				out_d[i]=(None, None)
			else:
				out_d[list(i.keys())[0]]=tuple(i[list(i.keys())[0]])
		config["files"] = out_d
	return config

# OS Functions
def get_tty_size():
	return [int(i) for i in subprocess.check_output(["stty","size"]).decode("utf-8").split()]

def get_open_sockets():
	out = [j for j in [i.split() for i in subprocess.check_output(["lsof", "-i", "-P"]).decode("utf-8").split("\n")[1:] if len(i)] if j[-1]=="(LISTEN)"]
	out_d = {}
	for i in out:
		out_d[int(i[8].split(":")[-1])]=(i[7], i[0], i[4], i[1])
	return out_d

# Setup Checks
def get_socket_checks(objects, config):
	checks = []
	for proto in config["listening"]:
		for r in config["listening"][proto]["ranges"]:
			checks.append(CheckSocketRange(r[0], r[1:], proto))
		for p in config["listening"][proto]["ports"]:
			checks.append(CheckSocket(p[0], p[1], proto))
	return checks

def get_file_checks(config):
	checks = []
	files = config["files"]
	for f in files:
		checks.append(FileCheck(None, f, files[f][0], files[f][1]))
	return checks

def get_service_checks(config):
	checks = []
	files = config["services"]
	for f in files:
		checks.append(ServiceCheck(None, f))
	return checks

def get_process_checks(config):
	checks = []
	processes = config["processes"]
	for process in processes:
		if type(process)==dict:
			n = list(process.keys())[0]
			checks.append(ProcessCheck(process[n], n))
		else:
			checks.append(ProcessCheck(None, process))
	return checks

def get_certificate_checks(config):
	checks = []
	certs = config["certificates"]
	for path in certs:
		domains = os.listdir(path)
		for i in domains:
			cert_p = os.path.join(path,i)
			cert_p = os.path.join(cert_p,"cert.pem")
			c = CertificateCheck(None, cert_p)
			if c.cert and not c.err:
				checks.append(c)
			else:
				print("[!] Error checking", path+":",c.err)
	return checks

def get_directory_checks(config):
	checks = []
	if type(config["directory"])==list:
		checks = [DirectoryContentCheck(None, i) for i in config["directory"]]
	elif type(config["directory"])==str:
		checks = [DirectoryContentCheck(None, config["directory"])]
	return checks

def get_apt_checks():
	return [AptUpdateCheck(None),AptUpdateCheck(None, security_only=True)]

# Check Processing
def run_checks(verbose=False):
	for i in checks:
		i.run(objects)
		if verbose: i.print_status()

def generate_report():
	out = {"states":{}}
	for i in checks:
		if i.type_id not in out["states"]: out["states"][i.type_id]={}
		if i.custom_content:
			out["states"][i.type_id]=i.custom_content
		else:
			out["states"][i.type_id][i.name]=i.status
	return out

def main(v=False):
	global objects, apt_data
	objects = get_open_sockets()
	run_checks(v)
	return generate_report()

# Socket Related
def get_bound_server_sock(port):
	server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server.bind(("", port))
	return server

def handle_request(d, a):
	host = a[0]
	if not host in WHITELIST or host in BLACKLIST:
		if CONNECTION_DEBUG: print("[*] Blocked Request from {}:{}".format(*a))
		return b""
	if CONNECTION_DEBUG: print("[*] Request from {}:{}".format(*a))
	try:
		chal = d.decode().replace("\n","")
	except:
		chal = "[ INVALID FORMATTING ]"
	if chal==CHALLENGE:
		return json.dumps(main(DEBUG)).encode("utf-8")
	else:
		if CONNECTION_DEBUG: print(" |- Invalid Challenge:", chal)
		if host in BLACKLIST_PENDING:
			if BLACKLIST_PENDING[host]>=STRIKE_LIMIT:
				BLACKLIST.append(host)
				del BLACKLIST_PENDING[host]
				if CONNECTION_DEBUG: print(" |- Blacklisting requestor...")
			else:
				if CONNECTION_DEBUG: print(" |- Adding Strike")
				BLACKLIST_PENDING[host]+=1
		else:
			if CONNECTION_DEBUG: print(" |- First Strike")
			BLACKLIST_PENDING[host]=1
		return b""

def listen_loop(port):
	s = get_bound_server_sock(port)
	# s.listen(5)
	while(1):
		d,a = s.recvfrom(1024)
		r= handle_request(d,a)
		if len(r):s.sendto(r,a)

if __name__ == '__main__':
	config = get_parameters(sys.argv[2])

	# Config
	BLACKLIST = []
	BLACKLIST_PENDING = {}
	STRIKE_LIMIT = 3
	CONNECTION_DEBUG = False
	if "-d" in sys.argv:
		sys.argv.pop(sys.argv.index("-d"))
		CONNECTION_DEBUG=True
	DEBUG = False
	if "-v" in sys.argv:
		sys.argv.pop(sys.argv.index("-v"))
		DEBUG=True
		if not CONNECTION_DEBUG: CONNECTION_DEBUG = True
	if DEBUG: print("[=] Starting with Verbose Output")
	if CONNECTION_DEBUG: print("[=] Starting with Connection Debug Output")
	CHALLENGE = "cd5f1e5e90"
	if "-c" in sys.argv:
		i = sys.argv.index("-c")
		sys.argv.pop(i)
		CHALLENGE = sys.argv.pop(i)
		print("[+] Custom Challenge Set.")
	elif "challenge" in config:
	 	CHALLENGE = config["challenge"]
		print("[+] Custom Challenge Set.")
	if DEBUG or CONNECTION_DEBUG: print(" |- Challenge: {}".format(CHALLENGE))
	WHITELIST = ["80.113.19.114"]

	objects = get_open_sockets()
	checks = []
	if "listening" in config: checks += get_socket_checks(objects, config)
	if "processes" in config: checks += get_process_checks(config)
	if "files" in config: checks += get_file_checks(config)
	if "certificates" in config: checks += get_certificate_checks(config)
	if "directory" in config: checks += get_directory_checks(config)
	if platform.system()=="Linux":
		if "services" in config: checks += get_service_checks(config)
		if "apt_updates" in config: checks+= get_apt_checks()

	listen_loop(int(sys.argv[1]))
