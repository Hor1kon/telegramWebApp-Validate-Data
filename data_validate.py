import hmac
import hashlib
import urllib.parse
import json
import time


def validate_telegram_data(init_data, bot_token):
    word = "query_id"
    word1 = "hash="
    print("before in")
    if word and word1 in init_data:
        data = dict(urllib.parse.parse_qsl(init_data))

        received_hash = data.pop('hash')

        data_check_string = '\n'.join([f'{k}={v}' for k, v in sorted(data.items())])

        # Generate the secret key using the bot token and the string
        secret_key = hmac.new(b"WebAppData", bot_token.encode('utf-8'), hashlib.sha256).digest()

        # Calculate the HMAC-SHA-256 signature of the data-check-string with the secret key
        calculated_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()

        if received_hash != calculated_hash:
            print("wrong hash")
            return False

        # Check the auth_date to prevent outdated data usage
        auth_date = int(data.get('auth_date'))
        current_time = int(time.time())
        if current_time - auth_date > 86400:  # 86400 seconds = 24 hours
            print("wrong time")
            return False

        return True
    else:
        return False


