# src/ocsp/app.py
import json
import base64
from typing import Dict, Any
import os
import logging
from shared.region_rotator import RegionRotator
from shared.network_logger import NetworkLogger

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Inicializamos los componentes
rotator = RegionRotator()
network_logger = NetworkLogger()

def get_raw_body(event: Dict[str, Any]) -> bytes:
    """Obtiene el body en formato raw binario"""
    if 'body' not in event:
        raise ValueError('No body in request')
    
    body = event['body']
    if event.get('isBase64Encoded', False):
        return base64.b64decode(body)
    return body.encode('utf-8') if isinstance(body, str) else body

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        # Extraemos la IP de origen
        source_ip = event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
        
        # Get raw OCSP request
        ocsp_request = get_raw_body(event)
        logger.info(f"Received OCSP request of size {len(ocsp_request)} bytes from {source_ip}")
        
        # Make request through random region
        response = rotator.make_request(
            method='POST',
            url=os.environ['OCSP_ENDPOINT'],
            source_ip=source_ip,
            body=ocsp_request,
            headers={
                'Content-Type': 'application/ocsp-request',
                'Accept': 'application/ocsp-response'
            }
        )
        
        return {
            'statusCode': response.status,
            'headers': {
                'Content-Type': 'application/ocsp-response',
                'Access-Control-Allow-Origin': '*'
            },
            'body': base64.b64encode(response.data).decode('utf-8'),
            'isBase64Encoded': True
        }
        
    except Exception as e:
        logger.error(f"Error processing OCSP request: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': str(e)})
        }