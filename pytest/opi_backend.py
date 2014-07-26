import socket
try:
	import simplejson as json
except ImportError:
	import json

defaultdump = True

class Client:

	def __init__(self, path="/tmp/opib"):
		self.con = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.con.connect(path)

	def _dorequest(self, req, dump):
		#print(req)
		s = json.dumps(req)
		b = bytes( s, 'utf-8')
		self.con.send(b)
		ret = self.con.recv(16384)
		return self._processreply(json.loads(ret.decode('utf-8')), dump)

	def _processreply(self, req, dump):
		if req["status"]["value"] == 0:
			if dump:
				print(json.dumps( req, indent=4 ))
			return (True,req)
		else:
			if dump:
				print("Request failed with error '%s'"%req["status"]["desc"])
			return (False,"Request failed with error '%s'"%req["status"]["desc"])


	def __del__(self):
		self.con.close()

class OPIBackend( Client ):

	def login(self, user, password, dump = defaultdump):
		req = {}
		req["cmd"] = "login"
		req["username"] = user
		req["password"] = password
		return self._dorequest(req, dump)

	def createuser(self, token, user, password, display, dump = defaultdump):
		req = {}
		req["cmd"] = "createuser"
		req["token"] = token
		req["username"] = user
		req["password"] = password
		req["displayname"] = display
		return self._dorequest(req, dump)


	def updateuserpassword(self, token, user, password, newpass, dump = defaultdump):
		req = {}
		req["cmd"] = "updateuserpassword"
		req["token"] = token
		req["username"] = user
		req["password"] = password
		req["newpassword"] = newpass
		return self._dorequest(req, dump)

	def updateuser(self, token, user, display, dump = defaultdump):
		req = {}
		req["cmd"] = "updateuser"
		req["token"] = token
		req["username"] = user
		req["displayname"] = display
		return self._dorequest(req, dump)

	def getuser(self, token, user, dump = defaultdump):
		req = {}
		req["cmd"] = "getuser"
		req["token"] = token
		req["username"] = user
		return self._dorequest(req, dump)

	def getusers(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "getusers"
		req["token"] = token
		return self._dorequest(req, dump)

	def deleteuser(self, token, user, dump = defaultdump):
		req = {}
		req["cmd"] = "deleteuser"
		req["token"] = token
		req["username"] = user
		return self._dorequest(req, dump)
