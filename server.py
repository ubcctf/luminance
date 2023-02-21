from twisted.enterprise import adbapi
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint, SSL4ServerEndpoint
from twisted.internet import reactor, ssl
from twisted.logger import Logger, textFileLogObserver, globalLogPublisher
from twisted.enterprise.adbapi import Transaction

from lumina_structs import *
from construct import StreamError

import hashlib, sys

class LuminaRPC(Protocol):

    def __init__(self, addr, reqAuth):
        self.authenticated = False
        self.user = None
        self.addr = addr
        self.reqAuth = reqAuth

    def dataReceived(self, data):
        #catch erroneous packets
        try:
            pkt, msg = rpc_message_parse(data)
            log.debug('Received {code}: {m}', code=pkt.code, m=msg)  #escape format string
        except StreamError as e:
            log.debug('Invalid data received from {host}: {error}', host=self.addr.host, error=e)
            self.transport.write(rpc_message_build(RPC_TYPE.RPC_FAIL, status=0, message='Invalid packet'))   #courteous response to avoid IDA from freezing in case it's an actual legit packet that we don't handle yet
            self.transport.loseConnection()
            return

        #auth
        if not self.authenticated:
            if pkt.code == RPC_TYPE.RPC_HELO:
                if self.reqAuth:
                    #TODO support HELOv2

                    #for the original packet, we auth with user and password in ida.key

                    #read the first line that starts with a null byte
                    #(IDA license check's MD5Update treats this as an empty line so we can safely put our content without breaking IDA)
                    if b'\0' in msg.hexrays_license:
                        user, password = [s.strip() for s in msg.hexrays_license.decode().split('\n\0', 3)[1:]]
                    elif len(authstr:=msg.hexrays_license.decode().strip().split('\n')) == 2:
                        #connecting client is third party that doesnt need to follow the ida.key format, also accept that as the auth string
                        user, password = [s.strip() for s in authstr]
                    else:
                        self.transport.write(rpc_message_build(RPC_TYPE.RPC_FAIL, status=0, message='No auth found'))
                        log.debug('No valid auth string found for {host}.', host=self.addr.host)
                        self.transport.loseConnection()
                        return

                    def check_hash(data):
                        if data:
                            iterations, salt, hash = data[0][0].split('$')
                            computed = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(iterations))
                            if computed.hex() != hash:
                                self.transport.write(rpc_message_build(RPC_TYPE.RPC_FAIL, status=0, message='Invalid password'))
                                log.debug('Invalid password attempted for {username} from {host}.', username=user, host=self.addr.host)
                                self.transport.loseConnection()
                                return
                            else:
                                self.transport.write(rpc_message_build(RPC_TYPE.RPC_OK))
                                log.debug('User {username} logged in successfully from {host}.', username=user, host=self.addr.host)
                                self.authenticated = True
                                self.user = user
                        else:
                            self.transport.write(rpc_message_build(RPC_TYPE.RPC_FAIL, status=0, message='Invalid user'))
                            log.debug('Invalid user {username} attempted from {host}.', username=user, host=self.addr.host)
                            self.transport.loseConnection()
                            return

                    #sqlite3 accepts a tuple
                    db.runQuery('SELECT password FROM users WHERE name = ?', (user,)).addCallback(check_hash)
                
                #no auth check; mainly for debugging purposes
                else:
                    self.transport.write(rpc_message_build(RPC_TYPE.RPC_OK))
                    log.debug('{host} has connected without auth.', host=self.addr.host)
                    self.authenticated = True
                    self.user = f'anonymous:{self.addr.host}'
            else:
                self.transport.write(rpc_message_build(RPC_TYPE.RPC_FAIL, status=0, message='Invalid handshake'))
                log.debug('Invalid packet type {code} sent from {host} during handshake.', code=pkt.code, host=self.addr.host)
                self.transport.loseConnection()
                return

        #handle rest of the packets
        else:
            if pkt.code == RPC_TYPE.PULL_MD:
                def reply_pull(data):
                    flags, mds = [], []
                    for sig in msg.funcInfos:
                        md = next((d for d in data if d[0] == sig.signature), None)
                        if md:
                            flags.append(ResultType.RES_OK)  #lumina uses 0 as found here
                            mds.append({
                                'metadata':{
                                    'func_name': md[1],
                                    'func_size': md[2],
                                    'serialized_data': {'data':md[3]}},   #RawCopy accepts raw bytes as data field, so we can skip parsing and rebuilding it every time
                                'popularity':md[4]})     #report internal ranking as popularity
                        else:
                            flags.append(ResultType.RES_NOT_FOUND)
                    self.transport.write(rpc_message_build(RPC_TYPE.PULL_MD_RESULT, found=flags, results=mds))
                    log.debug('Sent PULL_MD_RESULT: {result}', result=mds)

                db.runQuery(
                    'SELECT * FROM funcs WHERE signature IN (' + ','.join(['?']*len(msg.funcInfos)) + ') ORDER BY rank DESC',
                    tuple([info.signature for info in msg.funcInfos])
                ).addCallback(reply_pull)

            elif pkt.code == RPC_TYPE.PUSH_MD:
                def reply_push(data: list):
                    def insert_all_mds(transaction: Transaction):
                        transaction.executemany('INSERT INTO funcs VALUES(?,?,?,?,?,?);', [
                            (info.signature.signature, 
                            info.metadata.func_name, 
                            info.metadata.func_size, 
                            info.metadata.serialized_data.data, 
                            info.metadata.serialized_data.size + len(info.metadata.func_name),
                            self.user)
                        for info in msg.funcInfos])
                        log.debug('Wrote {count} functions ({new} with higher ranking) into the database.', count=len(msg.funcInfos), new=sum([d == ResultType.RES_ADDED for d in data]))
                        
                    db.runInteraction(insert_all_mds).addCallback(lambda d:   #we just wanna wait, d is ignored
                        self.transport.write(rpc_message_build(RPC_TYPE.PUSH_MD_RESULT, resultsFlags=data)))
                    
                def check_data_exists(transaction: Transaction) -> list:
                    exists = []
                    #determine rank of metadata from metadata payload
                    #for now, rank according to amount of metadata the payload includes (size of MetadataPayload), and also the length of the function name
                    #TODO consider time submitted into the weight too? to tiebreak metadata with similar size since the newer one is likely a more useful iteration
                    for info in msg.funcInfos:
                        transaction.execute('SELECT 1 FROM funcs WHERE signature = ? AND rank >= ?', (info.signature.signature, info.metadata.serialized_data.size + len(info.metadata.func_name)))
                        exists.append(ResultType.RES_ADDED if transaction.fetchone() is None else ResultType.RES_OK)  #if doesnt exist we flag it as 1 to signify success to lumina
                    return exists
                
                db.runInteraction(check_data_exists).addCallback(reply_push)

            else:
                self.transport.write(rpc_message_build(RPC_TYPE.RPC_FAIL, status=0, message='Unsupported packet'))
                log.debug('Unsupported packet type {code} sent from {host}, ignoring...', code=pkt.code, host=self.addr.host)


class LuminaRPCFactory(Factory):
    def __init__(self, reqAuth = True) -> None:
        super().__init__()
        self.reqAuth = reqAuth

    def buildProtocol(self, addr):
        return LuminaRPC(addr, self.reqAuth)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Runs a portable Lumina server at the specified host and port.')
    parser.add_argument('-i', '--interface', type=str, default="0.0.0.0", help='the address to listen on, defaults to 0.0.0.0')
    parser.add_argument('-p', '--port', type=int, default=4443, help='the port to listen on, defaults to 4443')
    parser.add_argument('-c', '--cert', type=argparse.FileType('rb'), default=None, help='enables TLS mode, specifying the certificate path that includes the key')
    parser.add_argument('-db', '--database', type=str, default='data.db', help='database file name, defaults to data.db')
    parser.add_argument('-na', '--noauth', action='store_true', help='Disable user authentication (for debugging/local use)')

    args = parser.parse_args()


    #TODO localize by passing log and db into factory
    log = Logger()


    db = adbapi.ConnectionPool('sqlite3', args.database, check_same_thread=False)

    #initialize database
    #TODO save last seen / hostname / license id / watermark?
    db.runQuery('CREATE TABLE IF NOT EXISTS users'
            +   '(name          TEXT PRIMARY KEY,'   #we don't expect a lot of users to be registered, so string as key should be alright
            +   ' password      TEXT);')
    #TODO save database / binary path / addresses?
    db.runQuery('CREATE TABLE IF NOT EXISTS funcs'
            +   '(signature     BLOB NOT NULL,'      #this is what we use to search up functions (but since it's not unique we can't make it primary key); assume all signatures are v1 for now
            +   ' name          TEXT,'
            +   ' size          INTEGER,'
            +   ' metadata      BLOB,'
            +   ' rank          INTEGER,'            #internal use only; for determining which metadata is more high quality and is to be returned on PULL_MD
            +   ' username      TEXT);') 


    if args.cert:
        #if the cert file doesnt have a key in pem format appended to it, openssl throws out arcane errors
        #aka you'd want to do sth like `openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out server.pem -days 365 -subj '/CN=www.maplebacon.org/O=Maple Bacon/C=XX' && cp server.pem client.pem && cat key.pem >> server.pem`
        #also -addext "subjectAltName =IP:127.0.0.1" will be needed for python >3.7 clients on localhost testing or else verify would fail
        cert = ssl.PrivateCertificate.loadPEM(args.cert.read())
        endpoint = SSL4ServerEndpoint(reactor, port=args.port, sslContextFactory=cert.options(), interface=args.interface)
    else:
        endpoint = TCP4ServerEndpoint(reactor, port=args.port, interface=args.interface)
        
    endpoint.listen(LuminaRPCFactory(not args.noauth))
    globalLogPublisher.addObserver(textFileLogObserver(sys.stdout))
    log.info(f'Server started at {args.interface}:{args.port} (TLS: {args.cert is not None}).')
    reactor.run()