import binascii
import time, json
MESSAGE_TYPE = [
    0x00, # 명령 또는 요청을 통해 응답을 기다림 (무시될 수 있음)
    0x01, # 실행 후 무시 요청 (A fire&forget request)
    0x02, # 응답을 대기하지 않고 notification 또는 event callback 요청
    0x80, # 응답 메시지
    0x81, # 에러를 포함하는 응답 메시지
# 이하는 TP Message Type으로 대상에서는 해당 type을 통해 Segment SOME/IP packet으로 인식함
    0x20, # 명령 또는 요청을 통해 응답을 기다림 (무시될 수 있음), TP 메시지
    0x21, # 실행 후 무시 요청 (A TP fire&forget request)
    0x22, # 응답을 대기하지 않고 notification 또는 event callback 요청, TP 메시지
    0x23, # TP 응답 메시지
    0x24, # 에러를 포함하는 TP 응답 메시지
]

RETURN_CODE = [
    0x00, # 에러가 발생하지 않음, REQUEST (0x00), REQUEST_NO_RETURN (0x01), NOTIFICATION (0x02) 사용
    0x01, # 에러가 발생함
    0x02, # 요청받은 Service ID가 존재하지 않음
    0x03, # 요청받은 Method ID가 존재하지 않음
    0x04, # Service ID 및 Method ID가 존재하나 애플리케이션이 실행되지 않음
    0x05, # 시스템에서 동작하는 서비스까지 요청 메시지가 전달되지 않음 (System Internal Error Code에 한함)
    0x06, # 지정된 Timeout이 지남
    0x07, # 요청한 SOME/IP Version을 지원하지 않음
    0x08, # Interface Version이 맞지 않음
    0x09, # Packet Deserialization 에러 발생
    0x0a, # 존재하지 않는 Message Type Value 수신
] 

class SOMEIP:
    ServiceName: str
    IP: str
    Port: int
    protocolType: int
    serviceID: bytes
    length: bytes
    methodID: bytes
    clientID: bytes
    sessionID: bytes
    someipVer: bytes
    interfaceVer: bytes
    messageType: bytes
    returnCode: bytes
    payload: bytearray
    
    def __init__(self, ServiceName, IP, Port, protocolType, serviceID, length, methodID, clientID, sessionID, someipVer, interfaceVer, messageType, returnCode, payload):
        self.ServiceName = ServiceName
        self.IP = IP
        self.Port = Port
        self.protocolType = protocolType
        self.serviceID = serviceID
        self.length = length
        self.methodID = methodID
        self.clientID = clientID
        self.sessionID = sessionID
        self.someipVer = someipVer
        self.interfaceVer = interfaceVer
        self.messageType = messageType
        self.returnCode = returnCode
        self.payload = payload

    def SendSomeIP(self)->str:
        """SomeIP Packet Send"""
        if self.protocolType:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.IP, self.Port))
        sock.settimeout(1)
        Data = self.serviceID + self.methodID + self.length + self.clientID + self.sessionID + self.someipVer + self.interfaceVer + self.messageType + self.returnCode
        sock.send(Data)
        try: 
            recv = sock.recv(1024)
            #print(":".join(hex(ord(char)) for char in recv))
            return str(self.ServiceName + "\n" + self.IP + "\n" + str(self.Port) + "\n" + hex(int.from_bytes(self.serviceID, 'big')) + "\n" + hex(int.from_bytes(self.methodID, 'big')))
        except socket.timeout:
            return ""

def hex_dump(buffer, start_offset=0):
    print('-' * 79)
 
    offset = 0
    while offset < len(buffer):
        # Offset
        print(' %08X : ' % (offset + start_offset), end='')
 
        if ((len(buffer) - offset) < 0x10) is True:
            data = buffer[offset:]
        else:
            data = buffer[offset:offset + 0x10]
 
        # Hex Dump
        for hex_dump in data:
            print("%02X" % hex_dump, end=' ')
 
        if ((len(buffer) - offset) < 0x10) is True:
            print(' ' * (3 * (0x10 - len(data))), end='')
 
        print('  ', end='')
 
        # Ascii
        for ascii_dump in data:
            if ((ascii_dump >= 0x20) is True) and ((ascii_dump <= 0x7E) is True):
                print(chr(ascii_dump), end='')
            else:
                print('.', end='')
 
        offset = offset + len(data)
        print('')
 
    print('-' * 79)

def GetVisualSOMEIP(data: bytearray):
    serviceID = data[0:2]
    MethodID = data[2:4]
    Length = data[4:8]
    clientID = data[8:10]
    SessionID = data[10:12]
    ProtocolVersion = data[12]
    InterfaceVersion = data[13]
    MessageType = data[14]
    ReturnCode = data[15]
    payload = data[16:]
    print("Message ID")
    print("\tService ID: 0x"+serviceID.hex())
    print("\tMethod ID: 0x"+MethodID.hex())
    print("Length: "+str(int.from_bytes(Length, 'big'))+" Bytes")
    print("Request ID")
    print("\tClient ID: 0x"+clientID.hex())
    print("\tSession ID: 0x"+SessionID.hex())
    print("Protocol Version: "+str(hex(ProtocolVersion)))
    print("Interface Version: "+str(hex(InterfaceVersion)))
    print("Message Type: "+str(hex(MessageType)))
    print("Return Code: "+str(hex(ReturnCode)))
    print("PAYLOAD")
    hex_dump(payload)
    
def SOMEIPLogger(Ip:str, Port:int, data: bytearray):
    log = {"Time":str(time.time()), "IP":Ip, "PORT":Port, "PAYLOAD": data.hex()}
    jsonStr = json.dumps(log)
    jsonlog = open("someipLogger.log", "a")
    jsonlog.write(jsonStr+"\n")
    jsonlog.close()
