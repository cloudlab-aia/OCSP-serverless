import http.server
import socketserver
import requests
import logging
import binascii
from urllib.parse import urlparse, parse_qs
import sys
import datetime
import json
import asn1crypto.ocsp
import asn1crypto.x509
import asn1crypto.crl
from io import BytesIO

# Configuración de logging avanzado
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('localProxy.log')
    ]
)
logger = logging.getLogger('CRL_OCSP_Proxy')

class DetailedDebugProxyHandler(http.server.BaseHTTPRequestHandler):

    AWS_API_GATEWAY_CRL  = "https://xxx3qwi566.execute-api.eu-north-1.amazonaws.com/prod/crl"
    AWS_API_GATEWAY_OCSP = "https://xxx3qwi566.execute-api.eu-north-1.amazonaws.com/prod/ocsp"

    def parse_ocsp_request(self, data):
        """Parsea y registra los detalles de una petición OCSP"""
        try:
            ocsp_req = asn1crypto.ocsp.OCSPRequest.load(data)
            
            logger.debug("\n=== OCSP Request Details ===")
            logger.debug("Version: %s", ocsp_req['tbs_request']['version'].native)
            
            for single_request in ocsp_req['tbs_request']['request_list']:
                req_cert = single_request['req_cert']
                logger.debug("\nRequested Certificate:")
                logger.debug("  Hash Algorithm: %s", req_cert['hash_algorithm']['algorithm'].native)
                logger.debug("  Issuer Name Hash: %s", binascii.hexlify(req_cert['issuer_name_hash'].native).decode())
                logger.debug("  Issuer Key Hash: %s", binascii.hexlify(req_cert['issuer_key_hash'].native).decode())
                logger.debug("  Serial Number: %s", req_cert['serial_number'].native)

            if ocsp_req['tbs_request']['requestor_name']:
                logger.debug("\nRequestor Name: %s", ocsp_req['tbs_request']['requestor_name'].native)

            extensions = ocsp_req['tbs_request']['request_extensions']
            if extensions:
                logger.debug("\nRequest Extensions:")
                for extension in extensions:
                    logger.debug("  %s: %s", extension['extn_id'].native, extension['extn_value'].native)

        except Exception as e:
            logger.error("Error parsing OCSP request: %s", str(e))

    def parse_ocsp_response(self, data):
        """Parsea y registra los detalles de una respuesta OCSP"""
        try:
            ocsp_resp = asn1crypto.ocsp.OCSPResponse.load(data)
            
            logger.debug("\n=== OCSP Response Details ===")
            logger.debug("Response Status: %s", ocsp_resp['response_status'].native)
            
            if ocsp_resp['response_bytes']:
                response_data = ocsp_resp['response_bytes']['response'].parsed
                logger.debug("Version: %s", response_data['tbs_response_data']['version'].native)
                logger.debug("Responder ID: %s", response_data['tbs_response_data']['responder_id'].native)
                logger.debug("Produced At: %s", response_data['tbs_response_data']['produced_at'].native)

                for single_response in response_data['tbs_response_data']['responses']:
                    cert_status = single_response['cert_status'].name
                    logger.debug("\nCertificate Status: %s", cert_status)
                    logger.debug("  This Update: %s", single_response['this_update'].native)
                    if single_response['next_update']:
                        logger.debug("  Next Update: %s", single_response['next_update'].native)

        except Exception as e:
            logger.error("Error parsing OCSP response: %s", str(e))

    def parse_crl(self, data):
        """Parsea y registra los detalles de una CRL"""
        try:
            crl = asn1crypto.crl.CertificateList.load(data)
            
            logger.debug("\n=== CRL Details ===")
            tbs = crl['tbs_cert_list']
            
            logger.debug("Version: %s", tbs['version'].native)
            logger.debug("Signature Algorithm: %s", crl['signature_algorithm']['algorithm'].native)
            logger.debug("Issuer: %s", tbs['issuer'].native)
            logger.debug("This Update: %s", tbs['this_update'].native)
            logger.debug("Next Update: %s", tbs['next_update'].native)
            
            revoked_certs = tbs['revoked_certificates']
            if revoked_certs:
                logger.debug("\nRevoked Certificates:")
                for cert in revoked_certs:
                    logger.debug("  Serial Number: %s", cert['user_certificate'].native)
                    logger.debug("  Revocation Date: %s", cert['revocation_date'].native)
                    if cert['crl_entry_extensions']:
                        logger.debug("  Reason: %s", cert['crl_entry_extensions'][0]['extn_value'].native)
                logger.debug("Total Revoked Certificates: %d", len(revoked_certs))
            else:
                logger.debug("No Revoked Certificates")

        except Exception as e:
            logger.error("Error parsing CRL: %s", str(e))

    def log_request_details(self, req_type=""):
        """Registra detalles completos de la petición HTTP"""
        logger.debug("\n%s", "="*70)
        logger.debug("Nueva petición %s - %s", req_type, datetime.datetime.now().isoformat())
        logger.debug("Method: %s", self.command)
        logger.debug("Path: %s", self.path)
        logger.debug("Protocol Version: %s", self.protocol_version)
        logger.debug("Client Address: %s", self.client_address)
        logger.debug("\nHeaders recibidos:")
        for header, value in self.headers.items():
            logger.debug("  %s: %s", header, value)

    def log_response_details(self, response):
        """Registra detalles completos de la respuesta"""
        logger.debug("\nDetalles de la respuesta:")
        logger.debug("Status Code: %d", response.status_code)
        logger.debug("Reason: %s", response.reason)
        logger.debug("\nHeaders de respuesta:")
        for header, value in response.headers.items():
            logger.debug("  %s: %s", header, value)
        logger.debug("Content Length: %d bytes", len(response.content))

    def do_GET(self):
        self.log_request_details("GET")
        try:
            if '.crl' in self.path or '/crl/' in self.path:
                logger.info("Procesando petición CRL: %s", self.path)
                
                # Realizar petición CRL
                response = requests.get(
                    f"{self.AWS_API_GATEWAY_CRL}{self.path}",
                    headers={'Accept': 'application/pkix-crl'},
                    timeout=10
                )
                
                # Log respuesta
                self.log_response_details(response)
                
                # Parsear y logear detalles de la CRL
                if response.status_code == 200:
                    self.parse_crl(response.content)
                
                # Enviar respuesta al cliente
                self.send_response(response.status_code)
                self.send_header('Content-Type', 'application/pkix-crl')
                self.send_header('Content-Length', str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)
            else:
                self.send_error(404)
        except Exception as e:
            logger.error("Error procesando petición GET CRL: %s", str(e), exc_info=True)
            self.send_error(500)

    def do_POST(self):
        self.log_request_details("POST")
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Parsear y logear detalles de la petición OCSP
            self.parse_ocsp_request(post_data)
            
            logger.debug("\nEnviando petición a AWS Gateway:")
            logger.debug("URL: %s", self.AWS_API_GATEWAY_OCSP)
            
            # Realizar petición OCSP
            response = requests.post(
                self.AWS_API_GATEWAY_OCSP,
                data=post_data,
                headers={
                    'Content-Type': 'application/ocsp-request',
                    'Accept': 'application/ocsp-response'
                },
                timeout=10
            )
            
            # Log respuesta
            self.log_response_details(response)
            
            # Parsear y logear detalles de la respuesta OCSP
            if response.status_code == 200:
                self.parse_ocsp_response(response.content)
            
            # Enviar respuesta al cliente
            self.send_response(response.status_code)
            self.send_header('Content-Type', 'application/ocsp-response')
            self.send_header('Content-Length', str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            logger.error("Error procesando petición POST OCSP: %s", str(e), exc_info=True)
            self.send_error(500)

def run_proxy(port=80):
    try:
        server_address = ('', port)
        httpd = socketserver.TCPServer(server_address, DetailedDebugProxyHandler)
        logger.info('CERT 5')
        logger.info('Proxy iniciado en puerto %d', port)
        logger.info('Log detallado en: proxy_debug.log')
        logger.info('OCSP endpoint: %s', DetailedDebugProxyHandler.AWS_API_GATEWAY_OCSP)
        logger.info('CRL endpoint: %s', DetailedDebugProxyHandler.AWS_API_GATEWAY_CRL)
        httpd.serve_forever()
    except PermissionError:
        logger.error("Error: Se requieren privilegios de administrador para el puerto %d", port)
        logger.info("Intentando puerto alternativo 8080...")
        run_proxy(8080)
    except Exception as e:
        logger.error("Error iniciando servidor: %s", str(e), exc_info=True)

if __name__ == "__main__":
    run_proxy()
