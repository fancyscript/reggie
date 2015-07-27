#!/usr/bin/env python

import socket
import optparse
import ssl
import time
from pymailinator.wrapper import Inbox



class ircbot(object):

	def __init__(self, server, port, nick, pword, ssl, apikey):

		self.server = server
		self.port = port
		self.nick = nick
		self.pword = pword
		self.email = None
		self.code = None
		self.ssl = ssl
		self.apikey = None
		self.mailname = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))


		self.status = {
			"data": None,
			"registered": False,
			"connected": False
			"verified": False

		}

	def self.getcode():
		try:
			inbox = Inbox(self.apikey)
			inbox.get(self.mailname)
			mail = inbox.messages[-1]
			mail.get_message()
			text = mail.body.split(" " + self.nick + " ")
			code = text[1].split()[0]

			self.code = code
		except:
			print("[-] Error Obtaining Verification Code. Check your API Key.")

	def self.changenick(self):
		irc.send("NICK " + self.nick + "\n\r")

		start = time.clock()
		while True:

			ircmsg = irc.recv()
			if ircmsg.find("PING :") != -1:
				self.pong(ircmsg)
			elif ircmsg.find("Please choose a different") != -1:
				return 0
			elif time.clock() - start > 20:
				return 1


	def self.pong(self, msg):
		try:
				irc.send("PONG :" + msg.split()[1] + "\n\r")
				print("[+] PONG")
		except:
			print("[-] Exception during PONG")

	def self.recv(self):
		self.status["data"]= irc.recv(2048).strip("\n\r")
		return self.status["data"]

	def self.register(self):
		try:
			irc.send("PRIVMSG nickserv: register " + self.pword + self.email + "\n\r")
			print("[+] Attempting Registration")
			print("[+] Nick: " + self.nick)
			print("[+] Password: " + self.pword)

			start = time.clock()
			while True:
				ircmsg = self.recv()
				if ircmsg.find("PING :") != -1:
					self.pong(ircmsg)
				elif ircmsg.find("is now registered to " + self.email) != -1:
					return 1
				elif ircmsg.find("GROUP") != -1:
					return -1

				elif time.clock() - start > 60:
					return 0
		except:
			print("[-] Error Sending Registration")

	def self.verify(self):
		try:
			irc.send("PRIVMSG nickserv: verify register " + self.nick + self.code)
			print("[+] Attempting Verification")
			print("[+] Nick: " + self.nick)
			print("[+] Code: " + self.code)

			start = time.clock()
			while True:
				ircmsg = self.recv()
				if ircmsg.find("PING :") != -1:
					self.pong(ircmsg)
				elif ircmsg.find("has now been verified.") != -1:
					return 1
				elif time.clock() - start > 20:
					return 0
			print("[-] Error Sending Verification")

def main():

	parser = optparse.OptionParser()
	parser.add_option("-s", "--server", help="Server to register your nick.", dest="server", action="store")
	parser.add_option("-p", "--port", help="Port on the server to connect through (usually 6667 or 6697 for SSL).", dest="port", action="store", type="int")
	parser.add_option("-n", "--nick", help="The nickname to register.", dest="nick", action="store")
	parser.add_option("-pw", "--password", help="Password with which to register the nickname.", dest="pword", action="store")
	#parser.add_option("-e", "--email", help="Email to send verification code.", dest="email")
	parser.add_option("-ssl", "--secure", help="Set if server uses SSL encryption.", dest="ssl", default=False, action="store_true")
	parser.add_option("-k", "--key", help="Your mailinator API key.", dest="key", action="store")

	(opts, args) = parser.parse_args()

	if opts.server is None:
	    print("Please specify a server.\n")
	    parser.print_help()
	    exit(-1)
	elif opts.nick is None:
	    print("Please specify a nickname.\n")
	    parser.print_help()
	    exit(-1)
	elif opts.pword is None:
	    print("Please specify a password.\n")
	    parser.print_help()
	    exit(-1)
	elif opts.key is None:
	    print("Please specify a Mailinator API key.\n")
	    parser.print_help()
	    exit(-1)

	if opts.port is None:
		if opt.ssl == True:
			opt.port = 6697
		else:
			opt.port = 6667
	    print("No port specified. Defaulting to %d \n", % opt.port)




	regbot = ircbot(opt.server, opt.port, opt.nick, opt.pword, opt.ssl, opt.key)
	while regbot.status["connected"] == False:
		try:
			irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			irc.connect((regbot.server, regbot.port))
			if regbot.ssl == True:
				irc = ssl.wrap_socket(irc)

			irc.send("USER "+ regbot.nick +" "+ regbot.nick +" "+ regbot.nick +" :Reggie!\n\r")
			if regbot.changenick() == 0:
				while regbot.changenick() == 0:
					print("[-] Nickname Taken: " + regbot.nick)
					newnick = input("Enter a new nickname (!quit to quit) > ")
					regbot.changenick()

			print("[+] Connected to " + regbot.server + ":" + regbot.port)
			regbot.status["connected"] = True
		except:
			retry = input("[+] Error Connecting to " + regbot.server + ":" + regbot.port ". Retry? (Y/N) > ")
			while retry != "Y" and retry != "N":
				retry = input("Not a valid option. Retry? (Y/N) > ")
			if retry == "Y":
				continue
			elif retry == "N":
				exit(0)

	try:
		print("Waiting to be able to register... (This should take about 2 minutes)")
		start_time = time.clock()

		while True:

			if (time.clock() - start_time > 60) and (regbot.status["registered"] == False):
				registration = regbot.register
				if registration == 1:
					print("[+] Registration Successful")
					regbot.status["registered"] = True
				elif registration == 0:
					print("[-] Registration Request Timed Out")
					exit(0)
				elif registration == -1:
					print("[-] Disconnect for a few minutes and try again.")
					exit(0)
			elif (regbot.status["codegot"] == False):
				regbot.getcode()
				print("[+] Code Received: " + regbot.code)
			elif (regbot.status["verified"] == False) and (regbot.code != None):
				verification = regbot.verify()
				if verification == 1:
					print("[+] Verification Successful")
					regbot.status["verified"] = True
				elif verification == 0:
					print("[-] Verification Request Timed Out")
					print("[!] If Verification Code is not Blank, Try Verifying Manually")
					exit(0)



			ircmsg = regbot.recv()
			if ircmsg.find("PING :") != -1:
				regbot.pong(ircmsg)



if __name__ == '__main__':
	main()



