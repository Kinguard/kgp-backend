import unittest
from opi_backend import OPIBackend
from subprocess import Popen
import signal
import time
import os

conf = {
	"exe":["../../opi-backend-build/opi-backend","-u","tor","-g","tor"],
	"sock":"/tmp/opib",
}

def waitfile(filename):
	found = False
	while not found:
		try:
			os.stat(filename)
			found = True
		except OSError:
			pass
		time.sleep(0.05)

class TestBase(unittest.TestCase):
	def _start(self):
		self.p = Popen(conf["exe"])
		waitfile(conf["sock"])
		self.s = OPIBackend()

	def _stop(self):
		self.p.send_signal(signal.SIGTERM)
		self.p.wait()

	def setUp(self):
		self._start()

	def tearDown(self):
		self._stop()


class TestOPIBackend( TestBase ):

	def test_01_login(self):
		(status, res) = self.s.login("test", "password")
		self.assertTrue( status )
		(status, res) = self.s.login("test", "password")
		self.assertTrue( status )
		(status, res) = self.s.login("Wrong user", "password")
		self.assertFalse( status )
		(status, res) = self.s.login("test", "wrong password")
		self.assertFalse( status )
		(status, res) = self.s.login("test", "")
		self.assertFalse( status )
		(status, res) = self.s.login("", "password")
		self.assertFalse( status )

	def test_02_createuser(self):
		(status, res) = self.s.login("tor", "test")
		self.assertTrue( status )
		(status, res) = self.s.createuser(res["token"], "test1", "password", "Display Name")
		self.assertTrue( status )


if __name__=='__main__':
	print("Start")
	unittest.main()
	print("Done!")