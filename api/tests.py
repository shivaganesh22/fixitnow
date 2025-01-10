import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account
import json

class FCMv1Sender:
    PROJECT_ID = 'fixitnow-698b4'
    SERVICE_ACCOUNT_JSON = {
                        "type": "service_account",
                        "project_id": "fixitnow-698b4",
                        "private_key_id": "6eed46c69d6289dd8bd2387f1ef2b3af36ad1b65",
                        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDbw5GbKAyBDKC\nSUOSonuECiZtHqcOvdzBpJKIKfLwX0egS3EpvRtt2K+V76TWxvsRa2CGjsefMXiy\nCDKHrFfiGytcDEG+lDFMzKNa8K56MD6uE6X0IC/EADYH6emohoTAkNOdJ5lyUSwz\n6NaW3ZUv7WzwYVkUa2G/YL5rqB/aoscWT2rn/8VMnPdP7WhMxtqodvQIpACateAu\nNjoVaxpyKjePB1qE5EqA8BWeSHYsNvX7GYxl3Ex8uEy8J059wWSSZ63CK1+7x7LI\nMr/Tx5PLNplNvDOejGdyT7Yfti5oj0IwBdh3hhKJt9cnlubu5BedpoGE3hQz7VV2\nT1h60L73AgMBAAECggEAPVVDlh9uEPRXQ6MphUHf4Jrs308A37P/LXhwEjKUDxLf\n4DL88zvpeUpJJJV+VndBAQEBXIk/pbq5ZaoD7adNN2UOcQdZtK0+YZtRYu9o2mj8\nqtX4vYpCY1Ero8Upst1wmRx6hPYSBpnp9OqMOfGVaeKpzzDF644dsZlzeUbcpFjn\n58dW1FqFBr7iTQxYaF9xz5ZO04NhydDSfBOaOdrQKXGitRHX0CzHKEOkGLO+GSIp\ngMja0TMF4970BwTxLr4uJYp4BnbCXZ7XGcKBhQkdG2qNZE2kQFiKfBg4fmTCIwME\nmf9rg+cLUYSBJj+YmIguDXve8YnpwHRDmsLvEhjvDQKBgQDsEJnq//ymhVZwRPhP\nXWd6TS6F6EPWsYJVzFq3OVfSAh5IMU5IDZNVQNOraVl0dAFUAeSVA8F3tMJvBadC\nNzXwrenjr3UatBWSTpbcMFHYuvlorQ9O2BqdZsvbwSYz10ggcLU/aZTJXEup+4GF\nOfZNXCpxTkkGokpmOf6CXMoxqwKBgQDT8BEwE4JthRpj9+/VO+wfbWXWPXlFfAKd\nVXP/6D3Z02for5KWiGkrTnPGTYFyMMqDf4KHBmxrQh2PbDfKqOt+ZrCdeILRDVTn\nVJc8of1P6iMnUbfyHLKDyx5t0bk29/MjpsgpcJbNCc1NmwAUs/Ev3p7XNTiZwlQG\n8+S5s2fz5QKBgEvgVijT2RiJGSyC7rFL23vTHRYLfuqeKb98LNhhxRmKdsNLndbJ\nDkdDzAV3mjo1I0wmQ5umFmRspGZdEdLVvi+7Jsd5WRGZOqnJOvJRUa1xA8OihJ4a\nFgvrw7DB146oLtXGhGt6e0lxshxT6+CvrbxV2IqM2CoatgE/uM+cFZ17AoGATgvL\n6I5mq3omm8XEFhw4+eHJbLm6nPHr7JB5ZTXbAQou66ssKi8Vu5LqY45LKwf4q7Ab\nGyosZts0E4rgiMrn3eZnB7ZHRkDIkV+/Sd7Fb9ZjF6mqOYiD3LDCBeMDd9CbQve6\nIjiJ7/u6FOgNgZI6MUyj5dB9hXHgi6bpBdGhaFkCgYEA3CDZXEg7Hz7aDJnrsn+q\nyGbkyH03xIaZkW0OvOziVsxvPaT39mFUsPR9nfcqwhDFAVgbsOZMey2HtmvRiwCu\nWD8hHrcCgO7FQSjTJY+zdQMqZuzp5/Mi+CMIX08TBiDSDU0bq9+mLd4bf7HrSrRe\nL4t8okHAtCo6gvZFUq/gu18=\n-----END PRIVATE KEY-----\n",
                        "client_email": "fixitnow-service-new@fixitnow-698b4.iam.gserviceaccount.com",
                        "client_id": "101186740008532573154",
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/fixitnow-service-new%40fixitnow-698b4.iam.gserviceaccount.com",
                        "universe_domain": "googleapis.com"
        }
    def __init__(self):
        
        self.credentials = service_account.Credentials.from_service_account_info(
            self.SERVICE_ACCOUNT_JSON,
            scopes=['https://www.googleapis.com/auth/firebase.messaging']
        )

    def get_access_token(self):
        self.credentials.refresh(Request())
        return self.credentials.token

    def send_message(self, registration_tokens, notification_title, notification_body,image):
        results = []
        for token in registration_tokens:
            # Construct message payload
            message = {
                'message': {
                    'token': token,
                    'notification': {
                        'title': notification_title,
                        'body': notification_body,
                        'image':image
                    }
                }
            }

            # Prepare headers
            headers = {
                'Authorization': f'Bearer {self.get_access_token()}',
                'Content-Type': 'application/json'
            }

            # FCM v1 endpoint
            url = f'https://fcm.googleapis.com/v1/projects/{self.PROJECT_ID}/messages:send'

            # Send request
            response = requests.post(url, headers=headers, json=message)
            results.append(response.json())

        return results

# Usage example
def main():
    # Service account JSON string
    


    
    REGISTRATION_TOKENS = [
        'etKD_jR7Q3aBPgZwzmLSnB:APA91bFptzKnQmnHZSB8F38qlzEy0XBoKYfA4BS6KT4RK-8N8xqyVNG2yYkQ4nybuF7HpZZc4m2PRNlLLOK-TU7fmG6iremOi6lxbh-NEAFI9nA0fAEwzg8',
       
    ]

    fcm_sender = FCMv1Sender()
    results = fcm_sender.send_message(
        REGISTRATION_TOKENS, 
        'Test Title', 
        'Test Message',
       "http://192.168.50.208:8000/media/uploads/1000003150_s0z2OQc.mp4",
    )
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
