#!/usr/bin/env python3
"""
Signature Verifier - Verify KMS signatures using public key
"""
import base64
import logging
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from typing import Tuple

logger = logging.getLogger(__name__)


class SignatureVerifier:
    """Verify signatures using KMS public key"""
    
    def __init__(self, region: str = 'us-east-1'):
        """
        Initialize signature verifier
        
        Args:
            region: AWS region (default: us-east-1)
        """
        self.region = region
        self.kms_client = boto3.client('kms', region_name=region)
        self._public_key_cache = {}
    
    def get_public_key(self, key_id: str) -> rsa.RSAPublicKey:
        """
        Get public key from KMS
        
        Args:
            key_id: KMS key ID or ARN
            
        Returns:
            RSA public key object
            
        Raises:
            RuntimeError: If failed to get public key
        """
        # Check cache first
        if key_id in self._public_key_cache:
            logger.debug(f"Using cached public key for {key_id}")
            return self._public_key_cache[key_id]
        
        try:
            logger.info(f"Fetching public key from KMS for key: {key_id}")
            
            response = self.kms_client.get_public_key(KeyId=key_id)
            
            # Parse public key
            public_key_der = response['PublicKey']
            public_key = serialization.load_der_public_key(
                public_key_der,
                backend=default_backend()
            )
            
            # Verify it's an RSA key
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Key is not an RSA public key")
            
            # Cache the key
            self._public_key_cache[key_id] = public_key
            
            logger.info(f"Public key retrieved successfully (key size: {public_key.key_size} bits)")
            
            return public_key
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            logger.error(f"KMS API error [{error_code}]: {error_msg}")
            raise RuntimeError(f"Failed to get public key: {error_msg}")
        except Exception as e:
            logger.error(f"Error getting public key: {e}", exc_info=True)
            raise RuntimeError(f"Failed to get public key: {e}")
    
    def verify_signature(self, message: str, signature: bytes, key_id: str) -> Tuple[bool, str]:
        """
        Verify signature using KMS public key
        
        Args:
            message: Original message that was signed
            signature: Signature bytes
            key_id: KMS key ID or ARN
            
        Returns:
            Tuple of (verification_result, details_message)
        """
        try:
            logger.info(f"Verifying signature for message: {message[:50]}...")
            
            # Get public key
            public_key = self.get_public_key(key_id)
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    message.encode('utf-8'),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                
                details = (
                    f"✓ Signature verification SUCCESSFUL\n"
                    f"  Message: {message}\n"
                    f"  Key ID: {key_id}\n"
                    f"  Signature length: {len(signature)} bytes\n"
                    f"  Algorithm: RSASSA_PKCS1_V1_5_SHA_256"
                )
                
                logger.info("Signature verification successful")
                return True, details
                
            except Exception as verify_error:
                details = (
                    f"✗ Signature verification FAILED\n"
                    f"  Message: {message}\n"
                    f"  Key ID: {key_id}\n"
                    f"  Error: {str(verify_error)}"
                )
                
                logger.warning(f"Signature verification failed: {verify_error}")
                return False, details
                
        except Exception as e:
            error_details = (
                f"✗ Verification error\n"
                f"  Error: {str(e)}"
            )
            logger.error(f"Verification error: {e}", exc_info=True)
            return False, error_details
    
    def get_key_info(self, key_id: str) -> dict:
        """
        Get detailed information about KMS key
        
        Args:
            key_id: KMS key ID or ARN
            
        Returns:
            Dictionary with key information
        """
        try:
            response = self.kms_client.describe_key(KeyId=key_id)
            key_metadata = response['KeyMetadata']
            
            return {
                'KeyId': key_metadata['KeyId'],
                'Arn': key_metadata['Arn'],
                'KeyUsage': key_metadata.get('KeyUsage', 'N/A'),
                'KeySpec': key_metadata.get('KeySpec', 'N/A'),
                'KeyState': key_metadata.get('KeyState', 'N/A'),
                'Description': key_metadata.get('Description', 'N/A')
            }
            
        except ClientError as e:
            logger.error(f"Failed to get key info: {e}")
            return {}
