
# src/crl/app.py
import json
import base64
from typing import Dict, Any
import os
import logging
from urllib.parse import urljoin
from shared.region_rotator import RegionRotator
from shared.network_logger import NetworkLogger

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Inicializamos los componentes
rotator = RegionRotator()
network_logger = NetworkLogger()

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        # Extraemos la IP de origen
        source_ip = event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
        
        # Extract path and build URL
        path = event.get('pathParameters', {}).get('proxy', '')
        if not path.startswith('/'):
            path = '/' + path
        url = urljoin(os.environ['CRL_ENDPOINT'], path)
        
        logger.info(f"Requesting CRL from {url} for client {source_ip}")
        
        # Make request through random region
        response = rotator.make_request(
            method='GET',
            url=url,
            source_ip=source_ip,
            headers={'Accept': 'application/pkix-crl'}
        )
        
        return {
            'statusCode': response.status,
            'headers': {
                'Content-Type': 'application/pkix-crl',
                'Access-Control-Allow-Origin': '*'
            },
            'body': base64.b64encode(response.data).decode('utf-8'),
            'isBase64Encoded': True
        }
        
    except Exception as e:
        logger.error(f"Error processing CRL request: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': str(e)})
        }
