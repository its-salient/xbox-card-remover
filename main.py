import requests
import threading
from colorama import Fore,init
import sys
import json
import re

request_exceptions = (requests.exceptions.SSLError,requests.exceptions.ProxyError,requests.exceptions.Timeout)
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
cfg : dict = json.load(open("config.json"))
thread_lock = threading.Lock()
proxies = cfg["proxies"]
def sprint(content, status: str="c") -> None:
    thread_lock.acquire()
    if status=="y":
        colour = Fore.YELLOW
    elif status=="c":
        colour = Fore.CYAN
    elif status=="r":
        colour = Fore.RED
    elif status=="new":
        colour = Fore.LIGHTYELLOW_EX
        thread_lock.acquire()
    sys.stdout.write(
            f"{colour}{content}"
            + "\n"
            + Fore.RESET
        )    
    thread_lock.release()
def remove_content(filename: str, delete_line: str) -> None:
        thread_lock.acquire()
        with open(filename, "r+") as io:
            content = io.readlines()
            io.seek(0)
            for line in content:
                if not (delete_line in line):
                    io.write(line)
            io.truncate()
        thread_lock.release()
def main(ms_creds : str):
    s = requests.session()
    if not proxies=="":
        s.proxies = {"https":str(proxies)}
    email = ms_creds.split("|")[0]
    password = ms_creds.split("|")[1]
    headers = {

    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Accept-Encoding': 'identity',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}

    while True:
        try:
            response = s.get('https://login.live.com/ppsecure/post.srf', headers=headers,timeout=20).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(str(e),"r")
            return
    try:
        ppft = response.split(''''<input type="hidden" name="PPFT" id="i0327" value="''')[1].split('"')[0]
        log_url = response.split(",urlPost:'")[1].split("'")[0]
    except:
        sprint("[-] Unknown Error (Proxies probably banned)")
        return
    log_data = f'i13=0&login={email}&loginfmt={email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894'
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
            }  
    while True:
        try:
            response = s.post(log_url,timeout=20,data=log_data,headers=headers).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return


    try:
        ppft2 = re.findall("sFT:'(.+?(?=\'))", response)[0],
        url_log2 = re.findall("urlPost:'(.+?(?=\'))", response)[0]
    except:
        sprint("[-] Invalid microsoft acc!","c")
        remove_content("accs.txt",ms_creds)
        return


    log_data2 = {
    "LoginOptions": "3",
    "type": "28",
    "ctx": "",
    "hpgrequestid": "",
    "PPFT": ppft2,
    "i19": "19130"
}
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://login.live.com',
        'Referer': log_url,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Sec-GPC': '1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
    }
    while True:
        try:
            midAuth2 = s.post(url_log2,timeout=20,data=log_data2,headers=headers).text
            break
        except request_exceptions:
            continue
        except Exception as e:
            sprint(e,"r")
            return
    while "fmHF" in midAuth2:
        midAuth2 = {
"fmHF": midAuth2.split('name="fmHF" id="fmHF" action="')[1].split('"')[0],
"pprid": midAuth2.split('type="hidden" name="pprid" id="pprid" value="')[1].split('"')[0],
"nap": midAuth2.split('type="hidden" name="NAP" id="NAP" value="')[1].split('"')[0],
"anon": midAuth2.split('type="hidden" name="ANON" id="ANON" value="')[1].split('"')[0],
"t": midAuth2.split('<input type="hidden" name="t" id="t" value="')[1].split('"')[0]} 
        data = {
    'pprid': midAuth2["fmHF"],
    'NAP': midAuth2['nap'],
    'ANON': midAuth2['anon'],
    't': midAuth2['t'],
}
        loda_lund = midAuth2['fmHF']
        while True:
            try:
                midAuth2 = s.post(loda_lund,data=data,headers={
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    # 'Cookie': 'display-culture=en-US; MicrosoftApplicationsTelemetryDeviceId=8c2b8809-97eb-4046-998e-710ac9d94bf0; MSFPC=GUID=6426b6c6378846b8ba38a219c60e10e9&HASH=6426&LV=202302&V=4&LU=1677313904985; ak_bmsc=503BA55230428C4CCE38BAA4072A528C~000000000000000000000000000000~YAAQHcITAvM1nDyGAQAAr1QsjBJ1lziRJTG02hd3wdgw0/8Bvf+1k8C/XXnZyx6sk126z3AlO0gdjwqIoOLiGxrPIDDMAaCIn5oQyCWBvQe14CZIBYugRCy7LOHvfHwFMTJ8f/HjNev2JjIFAyfuFfEloFJyoUbniTKgoW+mw3r7/e6ZWrbgz+3ok7dsuM7I2R0rW4TsIGosgBhi3KRv16A+V+tV/ePDKfis6z6OvXd8mq/CmP+pOrvvH9++J2YQE9kd0y5lRMtiTwqUl0YBy1Zky3UY/QRkodMdAosBrULRrqHjvbP8vnduKg7s2ai2WEJJj3gBqqHlc1nFGhv1BpJ2E3stii7rAzlb/23c3+JGH70h7fyxf517dHId73QWp/1GdQ==; AMCSecAuthJWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImJXOFpjTWpCQ25KWlMtaWJYNVVRRE5TdHZ4NCJ9.eyJ2ZXIiOiIyLjAiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkL3YyLjAiLCJzdWIiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFDVnRXSEJkRUxubi1BV0daOVdldXNVIiwiYXVkIjoiODFmZWFjZWQtNWRkZC00MWU3LThiZWYtM2UyMGEyNjg5YmI3IiwiZXhwIjoxNjc3NDc1MzYxLCJpYXQiOjE2NzczODg2NjEsIm5iZiI6MTY3NzM4ODY2MSwibmFtZSI6ImdpemNobyBhdGl0c28iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJnaXpjaG9hdGl0c29jQGhvdG1haWwuY29tIiwib2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTcyYTYtMzBlNGVlNjI5OWUyIiwidGlkIjoiOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkIiwibG9naW5faGludCI6Ik0kRWpWNG5PUDRkT2JRd25kM2I1eDV4Q2drbVo1WmxaeVJuMWlTV1ZLY24teVFrVi1TbTVpWm81ZWNueXN4NC1EbER5d0E5bjRVOVEiLCJwdWlkIjoiMDAwNkJGRkQyNzVGQ0Y5NyIsImFnZUdyb3VwIjozLCJhaW8iOiJEWXl6Z0R4Y0xBTkFZbE1Zczdaa3hMV0pJcDJCMTFiS1lHUTYwdDQwSWVWRnYyN2VPeG5MN2xIQUQzSGtYa3RoeUp6IWVha2Jvdzlvalp5R0tuKjRFa0JNWnBubVlQMklMMXZqbjVNIXd1SHVXTHN4dFo2S3Z2N2p5eG5HU2U0M2s4NFVhVXdSN1dCZWNnYUhLbjdJRTRvJCJ9.Q0f1cJKW30TN09O7Tn5fReykinZR-KQq0iDm4tW2sKEqpSz-oRHPyWriKsxgsyf425o-DKEMkddOGodL6rrNKvMHJMUF-UdYy2EVQpqX9LfiecXza_iX15llWvnBr3QJOd9gSkQ2HXBWTj0yBXyshA8c4f2tP33dRmgFaVePwyYfVWBKn5b_-EQepflhOfFsbXCAPYvffqLqN7g3My2X3Ef0ieWq2DK5oTyfbROQ_WiMdEevSCO2g6gC85xSK8Rpk0SzKWkJu9Bt6d6TL0xN2p87g7AO8SbA5d3isqbjwnUiCd3bfgu8I52LbMVrYiBjXoELMh9o3awsb1VxVfrdrQ; AMC-MS-CV=3icdaSHkZ0O6B6w4.5.0; bm_sv=A4E33E54E4DE78AB15702DC931F5AB2D~YAAQHcITAsA2nDyGAQAAw2UsjBKQb2Dy46001KPNu78PhivoGk4KwPoNK91T4NkyQjOi2BAvndxHGNOfmWIEZleitKQMeBozF7/tSUgXAdqLoX5VSlKjk1sLfgZzgsAzFycJ1GgRjuZX8AY7zIhfjA3yYLQWLNVXizsFKIx+g5GwqyT85NqZxrkn4S5aR0bKGQ/bx627865Q24O69yDMmIQg2CeEA5/GeykK5Ah13g93rqpvHh0CvTf7povvfE0Vw9u2~1',
    'Origin': 'https://login.live.com',
    'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
}).text     
                break
            except request_exceptions:
                continue
            except Exception as e:
                sprint(e,"r")
                return
    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.6',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
     'Referer': 'https://login.live.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-GPC': '1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': ua,
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

    params = {
    'fref': 'home.drawers.payment-options.manage-payment',
    'refd': 'account.microsoft.com',
}

    while True:
        try:
            response = s.get('https://account.microsoft.com/billing/payments', params=params, headers=headers)
            break
        except request_exceptions:continue
        except Exception as e:
            sprint(e,"r")
            return
    vrf_token = response.text.split('<input name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]
    headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.6',
    'Connection': 'keep-alive',
    'Correlation-Context': 'v=1,ms.b.tel.market=en-US,ms.b.tel.scenario=ust.amc.billing.payment-north-star,ms.c.ust.scenarioStep=PaymentNorthStarOboAuthStart',
    'MS-CV': 'zATvNJImJkOjVJ27.22.16',
    'Referer': 'https://account.microsoft.com/billing/payments?fref=home.drawers.payment-options.manage-payment&refd=account.microsoft.com',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'X-Requested-With': 'XMLHttpRequest',
    '__RequestVerificationToken': vrf_token,
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

    params = {
    'scopes': 'pidl',
}

    while True:
        try:
            response = s.get('https://account.microsoft.com/auth/acquire-onbehalf-of-token',params=params,headers=headers);break
        except request_exceptions:continue
        except Exception as e:sprint(e,"r");return
    ms_auth = "MSADELEGATE1.0=" + response.json()[0]["token"]
    headers = {
    'Accept': 'application/json',
    'Accept-Language': 'en-US,en;q=0.6',
    'Authorization': ms_auth,
    'Connection': 'keep-alive',
    'Content-Type': 'application/json',
    'Origin': 'https://account.microsoft.com',
    'Referer': 'https://account.microsoft.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'ms-cV': '/FGix5cmYTr0cIBeUxi2rQ.1',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

    while True:
        try:
            response = s.get(
    'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-US',
    headers=headers,
)
            break
        except request_exceptions:continue
        except Exception as e:sprint(e,"r");return
    try:
        pi_id = response.json()[0]["id"]
    except:
        sprint('[-] No card found on account!',"y")
        open("failed.txt",'a').write(ms_creds+'\n')
        remove_content("accs.txt",ms_creds)
        return
    headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.6',
    'Connection': 'keep-alive',
    'Origin': 'https://account.microsoft.com',
    'Referer': 'https://account.microsoft.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-GPC': '1',
    'User-Agent': ua,
    'authorization': ms_auth,
    'ms-cv': '/FGix5cmYTr0cIBeUxi2rQ.3',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

    params = {
    'partner': 'northstarweb',
    'language': 'en-US',
}

    response = s.delete(
    f'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx/{pi_id}',
    params=params,
    headers=headers,
)
    if response.status_code==204:
        sprint(f'[+] Removed card! {email}')
        open("success.txt","a").write(ms_creds+'\n')
        remove_content("accs.txt",ms_creds)
    else:
        sprint(response.text,"y")
        sprint(f'Failed to remove card! {email}',"y")
        open("failed.txt",'a').write(ms_creds+'\n')
        remove_content("accs.txt",ms_creds)

init()  
accs = open("accs.txt").read().splitlines()
threads = int(input(Fore.BLUE + "[?] Enter amount of threads -> "))

while len(accs) > 0:
    thread_lists = []
    for b in range(threads):
        acc = accs[0]
        start_thread = threading.Thread(target=main,args=(acc,))
        thread_lists.append(start_thread)
        start_thread.start()
        accs.pop(0)
    for threads_ in thread_lists:
        threads_.join()
