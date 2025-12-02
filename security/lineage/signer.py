# security/lineage/signer.py

import hmac
import hashlib
from typing import Union


class HMACSigner:
    """
    Simple HMAC-based signer for document integrity and origin assurance.

    This is a symmetric-key scheme:
      - the same secret key is used to create and verify signatures
      - keep this key in a secure vault / KMS in a real system
    """

    def __init__(self, secret_key: Union[str, bytes]) -> None:
        if isinstance(secret_key, str):
            secret_key = secret_key.encode("utf-8")
        self.secret_key = secret_key

    def sign(self, content: Union[str, bytes]) -> str:
        """
        Create a hex-encoded HMAC signature for the given content.

        :param content: Document content as string or bytes.
        :return: Hex-encoded HMAC.
        """
        if isinstance(content, str):
            content = content.encode("utf-8")

        mac = hmac.new(self.secret_key, content, hashlib.sha256)
        return mac.hexdigest()

    def verify(self, content: Union[str, bytes], signature: str) -> bool:
        """
        Verify that the provided signature matches the content.

        :param content: Document content as string or bytes.
        :param signature: Expected hex-encoded HMAC.
        :return: True if signature is valid, False otherwise.
        """
        expected = self.sign(content)
        # Use compare_digest to avoid timing attacks
        return hmac.compare_digest(expected, signature)
