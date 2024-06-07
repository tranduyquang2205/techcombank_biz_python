import requests
import json
import random
import hashlib
import base64
import time
import re
import os
from requests.cookies import RequestsCookieJar
import string
from urllib.parse import urlparse, parse_qs


class Techcombank:
    def __init__(self, username, password, account_number, device_id):
        self.file = f"db/users/{account_number}.json"
        self.cookies_file = f"db/cookies/{account_number}.json"
        self.session = requests.Session()
        self.state = self.get_imei()
        self.nonce = self.get_imei()
        self.code_verifier = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=96))
        self.code_challenge = self.get_code_challenge(self.code_verifier)
        self.cookies = RequestsCookieJar()
        self.username = username
        self.password = password
        self.account_number = account_number
        self.auth_token = None
        self.refresh_token = None
        self.identification_id = None
        self.name_account = None
        self.is_login = False
        self.balance = None
        self.id = None
        self.fullname = None
        self.pending_transfer = []
        self.service_agreement_id = None
        self.account_holder_names = None
        self.arrangements_ids = None
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.device_id = device_id
            self.fullname = None
            self.auth_token = None
            self.refresh_token = None
            self.is_login = False
            self.pending_transfer = []
            self.save_data()
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
            self.device_id = device_id
            self.save_data()
            

        self.init_data()
    def init_data(self):
        self.state = self.get_imei()
        self.nonce = self.get_imei()
        self.code_verifier = ''.join(random.choices(string.ascii_letters + string.digits, k=96))
        self.code_challenge = self.get_code_challenge(self.code_verifier)
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'identification_id': self.identification_id,
            'balance': self.balance,
            'id': self.id,
            'fullname': self.fullname,
            'is_login': self.is_login,
            'auth_token': self.auth_token,
            'refresh_token': self.refresh_token,
            'device_id': self.device_id,
            'pending_transfer': self.pending_transfer,
        }
        with open(f"db/users/{self.account_number}.json", 'w') as file:
            json.dump(data, file)
    def set_token(self, data):
        self.auth_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.time_set_token = time.time()
    def parse_data(self):
        with open(f"db/users/{self.account_number}.json", 'r') as file:
            data = json.load(file)
            self.username = data['username']
            self.password = data['password']
            self.account_number = data['account_number']
            self.identification_id = data['identification_id']
            self.balance = data['balance']
            self.id = data['id']
            self.fullname = data['fullname']
            self.is_login = data['is_login']
            self.auth_token = data['auth_token']
            self.refresh_token = data['refresh_token']
            self.device_id = data['device_id']
            self.pending_transfer = data['pending_transfer']
    def save_cookies(self,cookie_jar):
        # with open(self.cookies_file, 'w') as f:
        #     json.dump(cookie_jar.get_dict(), f)
        cookies = []
        for cookie in self.session.cookies:
            cookies.append({
                'Name': cookie.name,
                'Value': cookie.value,
                'Domain': cookie.domain,
                'Path': cookie.path,
                'Expires': cookie.expires,
                'Secure': cookie.secure,
                'HttpOnly': cookie.has_nonstandard_attr('HttpOnly')
            })
        with open(self.cookies_file, 'w') as file:
            json.dump(cookies, file, indent=4)
    def load_cookies(self):
        # try:
        #     with open(self.cookies_file, 'r') as f:
        #         cookies = json.load(f)
        #         self.cookies = cookies
        #         return
        # except (FileNotFoundError, json.decoder.JSONDecodeError):
        #     return requests.cookies.RequestsCookieJar()
        try:
            with open(self.cookies_file, 'r') as file:
                cookies = json.load(file)
                for cookie in cookies:
                    self.session.cookies.set(cookie['Name'], cookie['Value'])
        except FileNotFoundError:
            print(f"Cookies file {self.cookies_file} not found.")
        except json.JSONDecodeError:
            print(f"Error decoding cookies file {self.cookies_file}.")
    def get_login_url(self):
        headers = {
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.get_user_agent(),
        }

        url = f"https://business-id.techcombank.com.vn/auth/realms/backbase/protocol/openid-connect/auth?client_id=bb-web-client&redirect_uri=https%3A%2F%2Fbusiness.techcombank.com.vn%2Fredirect&state={self.state}&response_mode=fragment&response_type=code&scope=openid&nonce={self.nonce}&ui_locales=en-US%20vi&code_challenge={self.code_challenge}&code_challenge_method=S256"
        self.load_cookies()
        response = self.session.get(url, headers=headers)
        self.save_cookies(self.session.cookies)
        result = response.text

        matches = re.findall(r'form (.*)action="(.*)" method', result)
        if not matches or not matches[0] or not matches[0][1]:
            return None

        url = matches[0][1]
        return url

    def do_login(self):
        login_url = self.get_login_url()
        if not login_url:
            return {
                'status': 'SUCCESS',
                'message': 'Login successfully'
            }
        else:
            login_url = login_url.replace("&&", "&").replace("amp;", "&")
        headers = {
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
                'Cache-Control': 'max-age=0',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': self.get_user_agent()  
        }

        data = {
            'username': self.username,
            'password': self.password,
            'threatMetrixBrowserType': 'DESKTOP_BROWSER'
        }
        self.load_cookies()
        response = self.session.post(login_url, data=data, headers=headers)
        self.save_cookies(self.session.cookies)
        self.current_url = response.url

        result = response.text
        if 'Business Banking Web App' in result:
            return {
                'status': 'SUCCESS',
                'url': self.current_url,
                'message': 'Login successfully'
            }
        elif 'The username or password you entered is incorrect. Please try again' in result:
            return {
                'status': 'ERROR',
                'message': 'The username or password you entered is incorrect. Please try again'
            }
        elif 'An active session was closed when you logged in' in result:
            return self.do_login()
        else:
            return {
                'status': 'ERROR',
                'message': 'An error occurred. Please try again later!'
            }

    def check_session(self, url):
        headers = {
               'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
                'Cache-Control': 'max-age=0',
                'Connection': 'keep-alive',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Host': 'identity-tcb.techcombank.com.vn',
                'Origin': 'null',
                'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': self.get_user_agent()  
        }

        data = {
            'oob-authn-action': 'confirmation-poll'
        }
        self.load_cookies()
        res = self.session.post(url, headers=headers,data=data)
        self.save_cookies(self.session.cookies)
        result = res.text

        return result
    def continue_check_session(self, url):
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'identity-tcb.techcombank.com.vn',
            'Origin': 'null',
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.get_user_agent()  
        }

        data = {
            'oob-authn-action': 'confirmation-continue'
        }
        self.load_cookies()
        response = self.session.post(url, headers=headers,data=data,allow_redirects=False)
        self.save_cookies(self.session.cookies)
        if response.status_code == 302:
            new_url = response.headers.get('Location')
            return new_url
        else:
            return None
    def get_token(self,code, url):
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-type': 'application/x-www-form-urlencoded',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': 'bb-web-client',
            'redirect_uri': url if url != "" else 'https://business.techcombank.com.vn/redirect',
            'code_verifier': self.code_verifier,
            'ui_locales': 'en'
        }

        url = 'https://business-id.techcombank.com.vn/auth/realms/backbase/protocol/openid-connect/token'
        self.load_cookies()
        response = self.session.post(url, headers=headers, data=data)
        self.save_cookies(self.session.cookies)
        result = response.json()

        if 'access_token' in result:
            self.set_token(result)
            self.save_data()
        return result
    # Add other methods from the PHP class as needed
    def do_refresh_token(self):
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-type': 'application/x-www-form-urlencoded',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }

        data = {
            "grant_type": "refresh_token",
            "client_id": "bb-web-client",
            "refresh_token": self.refresh_token,
            "ui_locales": "en",
            "scope": "openid"
        }

        url = "https://business-id.techcombank.com.vn/auth/realms/backbase/protocol/openid-connect/token"

        response = self.session.post(url, data=data, headers=headers)
        result = response.json()

        if 'access_token' in result:
            self.set_token(result)
            self.save_data()

        return result
    def serviceagreements(self):
        # Load XSRF-TOKEN from cookies file
        xsrf_token = ""
        
        if self.cookies_file and os.path.exists(self.cookies_file):
            with open(self.cookies_file, 'r') as file:
                cookies = json.load(file)
                xsrf_token = next((cookie['Value'] for cookie in cookies if cookie['Name'] == 'XSRF-TOKEN'), "")
        

        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-type': 'application/x-www-form-urlencoded',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}',
            'X-XSRF-TOKEN': xsrf_token,
        }

        url = "https://business.techcombank.com.vn/api/access-control/client-api/v2/accessgroups/usercontext/serviceagreements?from=0&size=7"
        self.load_cookies()
        response = self.session.get(url, headers=headers)
        self.save_cookies(self.session.cookies)
        result = response.json()
        if len(result) > 0 and 'id' in result[0]:
            self.service_agreement_id = result[0]['id']
            self.account_holder_names = result[0]['name']

        return result
    def usercontext(self):
        # Load XSRF-TOKEN from cookies file
        xsrf_token = ""
        if self.cookies_file and os.path.exists(self.cookies_file):
            with open(self.cookies_file, 'r') as file:
                cookies = json.load(file)
                xsrf_token = next((cookie['Value'] for cookie in cookies if cookie['Name'] == 'XSRF-TOKEN'), "")

        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': f'Bearer {self.auth_token}',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': 'https://business.techcombank.com.vn',
            'Referer': 'https://business.techcombank.com.vn/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
            'X-XSRF-TOKEN': xsrf_token,
            'sec-ch-ua': '"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = {
            'serviceAgreementId': self.service_agreement_id,
        }
        self.load_cookies()
        response = self.session.post('https://business.techcombank.com.vn/api/access-control/client-api/v2/accessgroups/usercontext', headers=headers, json=data)
        self.save_cookies(self.session.cookies)
        response_body = response.text
        return response_body
    def get_info(self):
        self.serviceagreements()
        self.usercontext()
        # self.context()
        # self.me()
        # self.arrangement()
        # self.privileges()
        # self.aggregations()

        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-type': 'application/x-www-form-urlencoded',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}'
        }

        url = "https://business.techcombank.com.vn/api/arrangement-manager/client-api/v2/productsummary/context/arrangements?businessFunction=Product%20Summary%2CProduct%20Summary%20Limited%20View&resourceName=Product%20Summary&privilege=view&searchTerm=&from=0&size=12&ignoredProductKindNames=Term%20Deposit%2C%20FX%20booking%20Account&orderBy=name&direction=ASC"
        self.load_cookies()
        response = self.session.get(url, headers=headers)
        self.save_cookies(self.session.cookies)
        result = response.json()
        return result
    def arrangements(self):
        payload = json.dumps({
            "externalArrangementIds": [
                self.account_number
            ]
            })
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Host': 'onlinebanking.techcombank.com.vn',
            'Referer': 'https://onlinebanking.techcombank.com.vn/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}'
        }


        url = f'https://onlinebanking.techcombank.com.vn/api/sync-dis/client-api/v1/transactions/refresh/arrangements'
        self.load_cookies()
        response = self.session.post(url, headers=headers, data=payload)
        self.save_cookies(self.session.cookies)
        return response
    def sync(self):
        payload = json.dumps({
        "types": [
            "ACCOUNT"
        ],
        "refreshAll": True
        })
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Host': 'onlinebanking.techcombank.com.vn',
            'Referer': 'https://onlinebanking.techcombank.com.vn/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}'
        }


        url = f'https://onlinebanking.techcombank.com.vn/api/bb-ingestion-service/client-api/v2/accounts/sync'
        self.load_cookies()
        response = self.session.post(url, headers=headers, data=payload)
        self.save_cookies(self.session.cookies)
        return response
    
    def refresh_arrangements_transactions(self):
        xsrf_token = self.session.cookies.get('XSRF-TOKEN', '')

        headers = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-type': 'application/json',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'X-XSRF-TOKEN': xsrf_token,
            'Authorization': f'Bearer {self.auth_token}'
        }

        url = "https://business.techcombank.com.vn/api/arrangement-manager/client-api/v2/productsummary/context/arrangements?businessFunction=Product%20Summary&resourceName=Product%20Summary&privilege=view&size=1000000"

        response = self.session.get(url, headers=headers)
        result = response.json()

        if len(result) > 0 and 'id' in result[0]:
            self.arrangements_ids = result[0]['id']

        return result
    def get_transactions(self, from_date="2022-11-15", to_date="2022-11-15"):
        # Call required methods
        self.get_info()
        self.refresh_arrangements_transactions()

        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-type': 'application/x-www-form-urlencoded',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}'
        }

        url = f"https://business.techcombank.com.vn/api/transaction-manager/client-api/v2/transactions?bookingDateGreaterThan={from_date}&bookingDateLessThan={to_date}&arrangementsIds={self.arrangements_ids}&from=0&size=500&orderBy=bookingDate&direction=DESC"

        response = self.session.get(url, headers=headers)
        result = response.json()
        return result
            
            
            
    def get_transactions_by_page(self, from_date="2022-11-15", to_date="2022-12-03",limit=100,page=0):
        res = self.sync()
        res = self.arrangements()
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Content-type': 'application/x-www-form-urlencoded',
            'Host': 'onlinebanking.techcombank.com.vn',
            'Referer': 'https://onlinebanking.techcombank.com.vn/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': self.get_user_agent(),
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Authorization': f'Bearer {self.auth_token}'
        }


        url = f'https://onlinebanking.techcombank.com.vn/api/transaction-manager/client-api/v2/transactions?bookingDateGreaterThan={from_date}&bookingDateLessThan={to_date}&arrangementId={self.id}&from={page}&size={limit}&orderBy=bookingDate&direction=DESC'
        self.load_cookies()
        response = self.session.get(url, headers=headers)
        self.save_cookies(self.session.cookies)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return {
            'status': 'error',
            'msg': 'Please relogin!',
            'code': 401
        }

    def get_code_challenge(self, string):
        sha256_hash = hashlib.sha256(string.encode()).digest()
        base64_string = base64.b64encode(sha256_hash).decode()
        encrypted_string = base64_string.replace('+', '-').replace('/', '_').replace('=', '')
        return encrypted_string

    def is_json(self, string):
        try:
            json.loads(string)
            return True
        except json.JSONDecodeError:
            return False

    def get_microtime(self):
        return int(time.time() * 1000)

    def get_imei(self):
        time = hashlib.md5(str(self.get_microtime()).encode()).hexdigest()
        text = '-'.join([time[:8], time[8:12], time[12:16], time[16:20], time[17:]])
        text = text.upper()
        return text

    def get_user_agent(self):
        user_agent_array = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36 OPR/49.0.2725.47",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36 OPR/49.0.2725.64",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/62.0.3202.94 Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;  Trident/5.0)",
        "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/63.0.3239.84 Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.108 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS x86_64 9901.77.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.97 Safari/537.36"
                        ]
        return random.choice(user_agent_array)

    # Implement other methods as needed
def login_techcombank(user):
    # Create task before login to ask the phone to handle it
    # to do if need to call func to prepare phone
    
    login = user.do_login()
    if login['status'] == "SUCCESS":
        # print(json.dumps(login))
        code = None
        if 'url' in login:
            parsed_url = urlparse(login['url'])
            fragment = parsed_url.fragment or ''
            params = parse_qs(fragment)
            code = params.get('code', [None])[0]
            if code:
                code = code.replace('_', '')

        try:
            if code:
                token = user.get_token(code, "https://business.techcombank.com.vn/redirect")
            else:
                token = user.auth_token
            if token:
                return sync_balance_techcombank(user)
        except Exception as e:
            return e
    else:
        return login


def sync_balance_techcombank(user):
    try:
        ary_info = user.get_info()
        print(ary_info)
        ary_balance = {}
        ary_id = {}
        for acc in ary_info:
            if 'BBAN' in acc:
                ary_balance[acc['BBAN']] = acc['availableBalance']
                ary_id[acc['BBAN']] = acc['id']
            else:
                return {
                    'status': 'error',
                    'msg': 'Please relogin!',
                    'code': 401
                }

        if user.account_number in ary_balance:
            user.is_login = 'Đã đăng nhập'
            user.balance = ary_balance[user.account_number]
            user.id = ary_id[user.account_number]
            user.save_data()
            return {
                'status': 'success',
                'balance': user.balance,
                'code': 200
            }
    except:
        return {
                    'status': 'error',
                    'msg': 'Please relogin!',
                    'code': 401
                }

def sync_techcombank(user, start, end):
    d = user.do_refresh_token()
    ary_data = user.get_transactions(start, end)
    # print(ary_data)
    if not ary_data:
        return {
            'status': 'success',
            'msg': 'Không tìm thấy lịch sử giao dịch',
            'code': 200
        }
    if ('status' in ary_data and ary_data['status'] == 401) or ('error' in ary_data and ary_data['error'] == 'Unauthorized'):
        return {
            'status': 'error',
            'msg': 'Please relogin!',
            'code': 401
        }



    return ary_data

def refresh_token_user(user):
    return user.do_refresh_token()
def get_key_pos_number(number):
    line = (number - 1) // 3 + 1
    pos = (number - 1) % 3 + 1
    return f"{line}_{pos}"
# if __name__ == '__main__':
    # Example usage of the Techcombank class
    # while True:
    #     # user = Techcombank("0858393379", "Thuan@1704", "19072369596014", "")
    #     user = Techcombank("0358027860", "Dinh5500@", "19033744815017", "")

    #     #un comment login for first time, after that just call sync_balance_techcombank or sync_techcombank

    #     loginTechcombank(user)

    #     # balance = sync_balance_techcombank(user)
    #     # print(balance)
    #     transactions = sync_techcombank(user,"2024-04-01","2024-04-04",10000000)
    #     print(transactions)
    #     file_path = "output_tcb_04.04.json"
    #     with open(file_path, 'w') as json_file:
    #         json.dump(transactions, json_file, indent=4)

    #     print(f"JSON data has been saved to {file_path}")
    #     time.sleep(30)