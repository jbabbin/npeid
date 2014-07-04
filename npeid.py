#! /usr/bin/python
import os,sys,nids,re,pefile,peutils,StringIO,gzip,hashlib

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
signatures = peutils.SignatureDatabase('UserDB.TXT')

def handleTcpStream(tcp):
	#print "tcps -", str(tcp.addr), " state:", tcp.nids_state
	if tcp.nids_state == nids.NIDS_JUST_EST:
		((src, sport), (dst, dport)) = tcp.addr
		if dport in (80, 8000, 8080) or sport == 20:
			tcp.client.collect = 1
			tcp.server.collect = 1
	elif tcp.nids_state == nids.NIDS_DATA:
		tcp.discard(0)
	elif tcp.nids_state in end_states:
		toserver = tcp.server.data[:tcp.server.count]
                toclient = tcp.client.data[:tcp.client.count]
		((src, sport), (dst, dport)) = tcp.addr
		scan_tcp_body = None
		proto = None
		if dport in (80, 8000, 8080):
			proto = "HTTP"
			header_len = toclient.find('\r\n\r\n')
			get_request = toserver.split('\n')[0][:-1]
			host = toserver.split('\n')[1][:-1]
			print "%s" % str(get_request)
			print "%s" % str(host)
			try:
				gzip_data = toclient[header_len+4:]
				gzip_data = StringIO.StringIO(gzip_data)
				gzipper = gzip.GzipFile(fileobj=gzip_data)
				scan_tcp_body = gzipper.read()
			except:
				scan_tcp_body = toclient[header_len+4:]
		elif sport == 20:
			proto = "FTP"
			scan_tcp_body = toserver
		if scan_tcp_body.startswith('MZ'):
			if extract:
				h = hashlib.md5()
				h.update(scan_tcp_body)
				md5 = h.hexdigest()
				print "MD5: %s" % str(md5)
				f = open("%s.exe" % md5,'w')
				f.write(scan_tcp_body)
				f.close()
			pe = pefile.PE(data=scan_tcp_body)
			matches = signatures.match_all(pe, ep_only = True)
			for match in matches:
				print "%s - %s" % (proto, match)

def main():
	global extract
	extract = False
	pcap = False
	if "-e" in sys.argv:
		extract = True
	nids.param("scan_num_hosts", 0)
	for arg in sys.argv[1:]:
		if arg.endswith('.pcap'):
			pcap = True
			nids.param("filename", arg)
	if not pcap:
		nids.param("device", "eth0")
	nids.init()
	nids.register_tcp(handleTcpStream)
	try:
		nids.run()
	except nids.error, e:
		print "nids/pcap error:", e
	except KeyboardInterrupt:
		print "Control c"
		sys.exit(0)
	except Exception, e:
		print sys.exc_info()

if __name__ == '__main__':
	main()

