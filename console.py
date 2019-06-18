import yaml, json, socket, subprocess, sys, time, threading

_LAST_STATE_LENGTH = (0,0)
UPDATE_RATE = 5 #In seconds
if "-u" in sys.argv:
	i = sys.argv.index("-u")
	sys.argv.pop(i)
	UPDATE_RATE = float(sys.argv.pop(i))
REFRESH_RATE = 5 #In seconds
if "-r" in sys.argv:
	i = sys.argv.index("-r")
	sys.argv.pop(i)
	REFRESH_RATE = float(sys.argv.pop(i))
PINGBACK_MAX = 15
if "-pm" in sys.argv:
	i = sys.argv.index("-pm")
	sys.argv.pop(i)
	PINGBACK_MAX = float(sys.argv.pop(i))
CYCLE_TIME = 1
DEBUG = "-v" in sys.argv
if DEBUG: sys.argv.pop(sys.argv.index("-v"))
if DEBUG:
	print("[*] Configs:")
	print(" |- REFRESH_RATE =", REFRESH_RATE)
	print(" |- UPDATE_RATE =", UPDATE_RATE)
	print(" |- PINGBACK_MAX =", PINGBACK_MAX)
	print(" |- Cycle Time {}s".format(CYCLE_TIME))

outpost_objects = {}
outposts_byname = {}
class Outpost:
	def __init__(self, name, addr, challenge):
		self.name = name
		self.addr = addr
		self.challenge = challenge
		self.last_ping = time.time()
		self.count = 0
		self.status = None
		self.status_cached = None
	def req_status(self, s):
		try:
			s.sendto(self.challenge.encode("utf-8"),self.addr)
		except:
			pass
	def pingback(self, s=False):
		if self.status: self.status_cached = self.status
		if not s and self.last_ping and time.time()-self.last_ping>PINGBACK_MAX:
			self.status = None
	def set_status(self, status_j):
		self.last_ping = time.time()
		self.status = status_j

		self.count = len(self.status["states"])

class term_c:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

def get_outposts(path):
	with open(path) as op:
		outposts = yaml.load(op.read())
		return outposts["outposts"]

def add_outposts(outposts):
	for i in outposts:
		addr = tuple(outposts[i][0])
		o = Outpost(i, addr, outposts[i][1])
		outpost_objects[addr] = o

def get_tty_size():
	return [int(i) for i in subprocess.check_output(["stty","size"]).decode("utf-8").split()]

def unify(a,b):
	o = {}
	for i in a:
		for j in a[i]:
			if i not in o: o[j] = a[i][j]
	for i in b:
		for j in b[i]:
			if i not in o: o[j] = b[i][j]
	return o

def update_all(s):
	for o in outpost_objects:
		# print("sending", outpost_objects[o].name)
		outpost_objects[o].req_status(s)
		outpost_objects[o].pingback()

def get_responses(s):
	c = 0
	while(1):
		try:
			d,a = s.recvfrom(4096)
			json_d = json.loads(d.decode("utf-8"))
			# print(c, json_d,a)
			outpost_objects[a].set_status(json_d)
			c+=1
		except:
			pass

def get_all_states():
	out = {}
	for i in outpost_objects.values():
		if i.status:
			out[i.name] = {"states":i.status["states"], "failed":len([i.status["states"][j] for j in i.status["states"] if not i.status["states"][j]]), "passed":len([i.status["states"][j] for j in i.status["states"] if i.status["states"][j]])}
		else:
			out[i.name] = None #{"states":[], "failed":0, "passed":0}
	return out

def all_true(args):
	for i in args:
		# print(i)
		if (type(i)==int and i!=0) or (type(i)==bool and not i): return False
	return True

def gen_status(args):
	if all_true(args): return term_c.OKGREEN+"[ NORMAL ]  "+term_c.ENDC
	if len(args) == len([i for i in args if not i]):
		return term_c.FAIL+"[ FAILING ] "+term_c.ENDC
	return term_c.WARNING+"[ WARNING ]"+term_c.ENDC

def display_status(offset=5, clear=True):
	global _LAST_STATE_LENGTH
	out = ""
	width = lambda x: get_tty_size()[1]-offset-len(x)
	outpost_states = get_all_states()
	for outpost in sorted([i for i in outpost_states]):
		state = outpost_states[outpost]
		# print("handling", outpost, )
		if state:
			t = "[{}] Outpost '{}' Status:".format("✓", term_c.BOLD+outpost+term_c.ENDC)
			out += "{}{}{} \n".format(t, " "*(width(t)-4), term_c.OKGREEN+"[ ONLINE ]"+term_c.ENDC)
		else:
			state = [i for i in outpost_objects.values() if i.name==outpost][0].status_cached
			if state: t = "[!] Outpost '{}' Status (Cached):".format(term_c.BOLD+outpost+term_c.ENDC)
			else: t = "[!] Outpost '{}' Status:".format(term_c.BOLD+outpost+term_c.ENDC)
			out += "{}{}{}\n".format(t, " "*(width(t)-4), term_c.FAIL+"[ OFFLINE ]"+term_c.ENDC)
		if state:
			for type_s in sorted(state["states"]):
				# print(state["states"][type_s])
				type_state = gen_status([state["states"][type_s][j] for j in state["states"][type_s]])
				t_h = " |- {}:".format(type_s)
				out += "{}{}{}\n".format(t_h, " "*(width(t_h)-12), type_state)
				# print(type_s, state["states"][type_s])
				for j in sorted(state["states"][type_s]):
					i = state["states"][type_s][j]
					if type(i)==bool:
						l = "   {}- {}{}{}\n".format("|" if i else "#",j,"{}",term_c.OKGREEN+"[ OK ]   "+term_c.ENDC if i else term_c.FAIL+"[ Error ]"+term_c.ENDC)
					else:
						prefix = "|" if i else "#"
						color = term_c.OKGREEN if i else term_c.FAIL
						text = str(i)
						if type(i)==int:
							prefix = "|" if not i else "#"
							color = term_c.OKGREEN if i==0 else "\033[36m"
						l = "   {}- {}{}{}\n".format(prefix,j,"{}",color+"[ "+text+" ]"+(" "*(5-len(text)))+term_c.ENDC)
					l = l.replace("{}"," "*(width(l)+9))
					out += l
		out+="\n"
	if out[-1]=="\n": out=out[:-1]
	if clear: clear_display()
	out = out[:-1]
	_LAST_STATE_LENGTH = (len(out.split("\n")), len(out))
	print(out)

def clear_display():
	w = get_tty_size()[1]
	sys.stdout.write(("\033[F"*(_LAST_STATE_LENGTH[0])))#+
	sys.stdout.write((((" "*w)+"\n")*(_LAST_STATE_LENGTH[0])))
	sys.stdout.write(("\033[F"*(_LAST_STATE_LENGTH[0]+1)))
	print()

# def main_loop1(server):
# 	print()
# 	try:
# 		while(1):
# 			update_all(server)
# 			get_responses(server)
# 			# display_status()
# 			# time.sleep(REFRESH_RATE)
# 			# clear_display()
# 	except KeyboardInterrupt:
# 		return

def main_loop(server):
	t_u = time.time()-UPDATE_RATE-1
	t_r = time.time()-REFRESH_RATE-1
	try:
		while(1):
			t = time.time()
			if t-t_u>UPDATE_RATE:
				update_all(server)
				t_u = t
			if t-t_r>REFRESH_RATE:
				display_status()
				t_r = t
			try:
				d,a = server.recvfrom(4096)
				json_d = json.loads(d.decode("utf-8"))
				outpost_objects[a].set_status(json_d)
			except Exception as e:
				# print(e)
				pass
			time.sleep(CYCLE_TIME)
	except KeyboardInterrupt:
		print("\n[*] Exiting...")
		return

if __name__ == '__main__':
	o = get_outposts(sys.argv[1])
	add_outposts(o)
	server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server.setblocking(False)
	main_loop(server)
