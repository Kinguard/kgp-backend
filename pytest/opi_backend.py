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

	def authenticate(self, user, password, dump = defaultdump):
		req = {}
		req["cmd"] = "authenticate"
		req["username"] = user
		req["password"] = password
		return self._dorequest(req, dump)

	def shutdown(self, token, shutdown, dump = defaultdump):
		req = {}
		req["cmd"] = "shutdown"
		req["token"] = token
		req["action"] = "shutdown" if shutdown else "reboot"
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

	def getusers(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "getusers"
		req["token"] = token
		return self._dorequest(req, dump)

	def getuser(self, token, user, dump = defaultdump):
		req = {}
		req["cmd"] = "getuser"
		req["token"] = token
		req["username"] = user
		return self._dorequest(req, dump)

	def userexists(self, user, dump = defaultdump):
		req = {}
		req["cmd"] = "getuserexists"
		req["username"] = user
		return self._dorequest( req, dump )

	def getusergroups(self, user, dump = defaultdump):
		req = {}
		req["cmd"] = "getusergroups"
		req["username"] = user
		return self._dorequest( req, dump )

	def updateuser(self, token, user, display, dump = defaultdump):
		req = {}
		req["cmd"] = "updateuser"
		req["token"] = token
		req["username"] = user
		req["displayname"] = display
		return self._dorequest(req, dump)

	def deleteuser(self, token, user, dump = defaultdump):
		req = {}
		req["cmd"] = "deleteuser"
		req["token"] = token
		req["username"] = user
		return self._dorequest(req, dump)

	def getgroups(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "groupsget"
		req["token"] = token
		return self._dorequest(req, dump)

	def addgroup(self, token, group, dump = defaultdump):
		req = {}
		req["cmd"] = "groupadd"
		req["token"] = token
		req["group"] = group
		return self._dorequest(req, dump)

	def addgroupmember(self, token, group, member, dump = defaultdump):
		req = {}
		req["cmd"] = "groupadd"
		req["token"] = token
		req["group"] = group
		req["member"] = member
		return self._dorequest(req, dump)

	def getgroupmembers(self, token, group, dump = defaultdump):
		req = {}
		req["cmd"] = "groupgetmembers"
		req["token"] = token
		req["group"] = group
		return self._dorequest(req, dump)

	def removegroup(self, token, group, dump = defaultdump):
		req = {}
		req["cmd"] = "groupremove"
		req["token"] = token
		req["group"] = group
		return self._dorequest(req, dump)

	def removegroupmember(self, token, group, member, dump = defaultdump):
		req = {}
		req["cmd"] = "groupremovemember"
		req["token"] = token
		req["group"] = group
		req["member"] = member
		return self._dorequest(req, dump)

	def getbackupsettings(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "backupgetsettings"
		req["token"] = token
		return self._dorequest(req, dump)

	def setbackupsettings(self, token, location, backuptype, dump = defaultdump):
		req = {}
		req["cmd"] = "backupsetsettings"
		req["token"] = token
		req["location"] = location
		req["type"] = backuptype
		return self._dorequest(req, dump)

	def getbackupquota(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "backupgetquota"
		req["token"] = token
		return self._dorequest(req, dump)

	def getbackupstatus(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "backupgetstatus"
		req["token"] = token
		return self._dorequest(req, dump)

	def setupdatesettings(self, token, updatestate, dump = defaultdump):
		req = {}
		req["cmd"] = "updatesetstate"
		req["token"] = token
		req["state"] = updatestate
		return self._dorequest(req, dump)

	def getupdatesettings(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "updategetstate"
		req["token"] = token
		return self._dorequest(req, dump)

	def getsmtpdomains(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpgetdomains"
		req["token"] = token
		return self._dorequest(req, dump)

	def addsmtpdomain(self, token, domain, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpadddomain"
		req["token"] = token
		req["domain"] = domain
		return self._dorequest(req, dump)

	def removesmtpdomain(self, token, domain, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpdeletedomain"
		req["token"] = token
		req["domain"] = domain
		return self._dorequest(req, dump)

	def getsmtpaddresses(self, token, domain, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpgetaddresses"
		req["token"] = token
		req["domain"] = domain
		return self._dorequest(req, dump)

	def addsmtpaddresses(self, token, domain, address, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpaddaddress"
		req["token"] = token
		req["domain"] = domain
		req["address"] = address
		return self._dorequest(req, dump)

	def deletesmtpaddresses(self, token, domain, address, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpdeleteaddress"
		req["token"] = token
		req["domain"] = domain
		req["address"] = address
		return self._dorequest(req, dump)

	def getsmtpsettings(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpgetsettings"
		req["token"] = token
		return self._dorequest(req, dump)

	def setsmtpcustom(self, token, relay, user, password, port, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpsetsettings"
		req["token"] = token
		req["type"] = "CUSTOM"
		req["relay"] = relay
		req["username"] = user
		req["password"] = password
		req["port"] = port
		return self._dorequest(req, dump)

	def setsmtpexternal(self, token, send, receive, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpsetsettings"
		req["token"] = token
		req["type"] = "EXTERNAL"
		req["send"] = send
		req["receive"] = receive
		return self._dorequest(req, dump)

	def setsmtpopi(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "smtpsetsettings"
		req["token"] = token
		req["type"] = "OPI"
		return self._dorequest(req, dump)

	def getfetchmailaccounts(self, token, username, dump = defaultdump):
		req = {}
		req["cmd"] = "fetchmailgetaccounts"
		req["token"] = token
		req["username"] = username
		return self._dorequest(req, dump)

	def getfetchmailaccount(self, token, hostname, identity, dump = defaultdump):
		req = {}
		req["cmd"] = "fetchmailgetaccount"
		req["token"] = token
		req["hostname"] = hostname
		req["identity"] = identity
		return self._dorequest(req, dump)

	def addfetchmailaccount(self, token, email, hostname, identity, password, username, ssl, dump = defaultdump):
		req = {}
		req["cmd"] = "fetchmailaddaccount"
		req["token"] = token
		req["email"] = email
		req["hostname"] = hostname
		req["identity"] = identity
		req["password"] = password
		req["username"] = username
		req["ssl"] = ssl
		return self._dorequest(req, dump)

	def updatefetchmailaccount(self, token, email, hostname, identity, password, username, ssl, dump = defaultdump):
		req = {}
		req["cmd"] = "fetchmailupdateaccount"
		req["token"] = token
		req["email"] = email
		req["hostname"] = hostname
		req["identity"] = identity
		req["password"] = password
		req["username"] = username
		req["ssl"] = ssl
		return self._dorequest(req, dump)

	def removefetchmailaccount(self, token, hostname, identity, dump = defaultdump):
		req = {}
		req["cmd"] = "fetchmaildeleteaccount"
		req["token"] = token
		req["hostname"] = hostname
		req["identity"] = identity
		return self._dorequest(req, dump)

	def getportstatus(self, token, port, dump = defaultdump):
		req = {}
		req["cmd"] = "networkgetportstatus"
		req["token"] = token
		req["port"] = port
		return self._dorequest(req, dump)

	def setportstatus(self, token, port, set_open, dump = defaultdump):
		req = {}
		req["cmd"] = "networksetportstatus"
		req["token"] = token
		req["port"] = port
		req["set_open"] = set_open
		return self._dorequest(req, dump)

	def getopiname(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "networkgetopiname"
		req["token"] = token
		return self._dorequest(req, dump)

	def setopiname(self, token, hostname, dump = defaultdump):
		req = {}
		req["cmd"] = "networksetopiname"
		req["token"] = token
		req["hostname"] = hostname
		return self._dorequest(req, dump)

	def setnetworksettings(self, token, cfgtype, ipnumber, netmask, gateway, dns, dump = defaultdump):
		req = {}
		req["cmd"] = "setnetworksettings"
		req["token"] = token
		req["type"] = cfgtype
		req["ipnumber"] = ipnumber
		req["netmask"] = netmask
		req["gateway"] = gateway
		req["dns"] = dns
		return self._dorequest(req, dump)

	def getnetworksettings(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "getnetworksettings"
		req["token"] = token
		return self._dorequest(req, dump)

	def getshellsettings(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "getshellsettings"
		req["token"] = token
		return self._dorequest(req, dump)

	def setshellenabled(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "doshellenable"
		req["token"] = token
		return self._dorequest(req, dump)

	def setshelldisabled(self, token, dump = defaultdump):
		req = {}
		req["cmd"] = "doshelldisable"
		req["token"] = token
		return self._dorequest(req, dump)
